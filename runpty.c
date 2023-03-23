/*
 * Copyright (c) 2011-2015, 2017-2023: Todd C. Miller <Todd.Miller@sudo.ws>
 * Copyright (c) 2023 Duncan Overbruck <mail@duncano.de>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <sys/fcntl.h>
#include <sys/poll.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <errno.h>
#include <limits.h>
#include <paths.h>
#include <pty.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef _PATH_TTY
#define "/dev/tty"
#endif

/* TCSASOFT is a BSD extension that ignores control flags and speed. */
#ifndef TCSASOFT
#define TCSASOFT 0
#endif

static int selfpipe[2];

static void
sighandler(int signo)
{
	while (write(selfpipe[1], &signo, sizeof(signo)) == -1 && errno == EINTR)
		;
}

static volatile sig_atomic_t got_sigttou;

static void
sigttou(int signo)
{
	(void) signo;
	got_sigttou = 1;
}
static volatile sig_atomic_t got_sigttin;

static void
sigttin(int signo)
{
	(void) signo;
	got_sigttin = 1;
}

static bool tty_initialized;

/*
 * Like tcsetattr() but restarts on EINTR _except_ for SIGTTOU.
 * Returns 0 on success or -1 on failure, setting errno.
 * Sets got_sigttou on failure if interrupted by SIGTTOU.
 */
static int
tcsetattr_nobg(int fd, int flags, struct termios *tp)
{
    struct sigaction sa, osa;
    int rc;

    /*
     * If we receive SIGTTOU from tcsetattr() it means we are
     * not in the foreground process group.
     * This should be less racy than using tcgetpgrp().
     */
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = sigttou;
    got_sigttou = 0;
    sigaction(SIGTTOU, &sa, &osa);
    do {
	rc = tcsetattr(fd, flags, tp);
    } while (rc != 0 && errno == EINTR && !got_sigttou);
    sigaction(SIGTTOU, &osa, NULL);

    return rc;
}

/* Termios flags to copy between terminals. */
#define INPUT_FLAGS (IGNPAR|PARMRK|INPCK|ISTRIP|INLCR|IGNCR|ICRNL|IUCLC|IXON|IXANY|IXOFF|IMAXBEL|IUTF8)
#define OUTPUT_FLAGS (OPOST|OLCUC|ONLCR|OCRNL|ONOCR|ONLRET)
#define CONTROL_FLAGS (CS7|CS8|PARENB|PARODD)
#define LOCAL_FLAGS (ISIG|ICANON|XCASE|ECHO|ECHOE|ECHOK|ECHONL|NOFLSH|TOSTOP|IEXTEN|ECHOCTL|ECHOKE|PENDIN)

static int
term_copy(int src, int dst)
{
	struct termios tt_src, tt_dst;
	struct winsize wsize;
	speed_t speed;

	if (tcgetattr(src, &tt_src) == -1 || tcgetattr(dst, &tt_dst) == -1)
		return -1;

	/* Clear select input, output, control and local flags. */
	tt_dst.c_iflag &= ~(INPUT_FLAGS);
	tt_dst.c_oflag &= ~(OUTPUT_FLAGS);
	tt_dst.c_cflag &= ~(CONTROL_FLAGS);
	tt_dst.c_lflag &= ~(LOCAL_FLAGS);

	/* Copy select input, output, control and local flags. */
	tt_dst.c_iflag |= (tt_src.c_iflag & INPUT_FLAGS);
	tt_dst.c_oflag |= (tt_src.c_oflag & OUTPUT_FLAGS);
	tt_dst.c_cflag |= (tt_src.c_cflag & CONTROL_FLAGS);
	tt_dst.c_lflag |= (tt_src.c_lflag & LOCAL_FLAGS);

	/* Copy special chars from src verbatim. */
	for (int i = 0; i < NCCS; i++)
		tt_dst.c_cc[i] = tt_src.c_cc[i];

	/* Copy speed from src (zero output speed closes the connection). */
	if ((speed = cfgetospeed(&tt_src)) == B0)
		speed = B38400;
	cfsetospeed(&tt_dst, speed);
	speed = cfgetispeed(&tt_src);
	cfsetispeed(&tt_dst, speed);
	if (tcsetattr_nobg(dst, TCSASOFT|TCSAFLUSH, &tt_dst) == -1)
		return -1;

	if (ioctl(src, TIOCGWINSZ, &wsize) == 0)
		ioctl(dst, TIOCSWINSZ, &wsize);

	return 0;
}

static int
monitor_handle_sigchld(pid_t child, int backchannel)
{
	int status;
	pid_t pid;
	do {
		pid = waitpid(child, &status, WUNTRACED|WNOHANG);
	} while (pid == -1 && errno == EINTR);
	if (pid == -1) {
		perror("waitpid");
		return 0;
	}
	if (pid == 0)
		return 0;
	if (WIFEXITED(status)) {
		/* status = WEXITSTATUS(status); */
	} else if (WIFSIGNALED(status)) {
		/* fprintf(stderr, "%s%s\n", strsignal(WTERMSIG(status)), */
		/* 		WCOREDUMP(status) ? " (core dumped)" : ""); */
		/* status = WTERMSIG(status) + 128; */
	} else if (WIFSTOPPED(status)) {
		/* fprintf(stderr, "%s%s %d\n", strsignal(WSTOPSIG(status)), */
		/* 		WCOREDUMP(status) ? " (core dumped)" : "", WSTOPSIG(status)); */
		/* kill(getppid(), WSTOPSIG(status)); */
	} else {
		/* XXX: unexpected */
	}
	while (send(backchannel, &status, sizeof(status), 0) == -1) {
		if (errno != EINTR && errno != EAGAIN) {
			perror("unable to send message to monitor process");
			exit(1);
		}
	}
	return 0;
}

static int
monitor_handle_signal(int fd, pid_t child, int backchannel)
{
	int signo = 0;
	while (read(fd, &signo, sizeof(signo)) == -1) {
		if (errno != EINTR && errno != EAGAIN) {
			perror("unable to read signal");
			exit(1);
		}
	}
	switch (signo) {
	case 0: return 0;
	case SIGCHLD:
		monitor_handle_sigchld(child, backchannel);
	default:
		/* Forward signal */
		break;
	}
	return 0;
}

enum cmd {
	CMD_CONT_FG = 'f',
	CMD_CONT_BG = 'b',
};

static int
monitor_handle_backchannel(int fd, int usertty, int follower, pid_t child, pid_t pgrp)
{
	enum cmd cmd = 0;
	/* Wait until the proxy process notifies us about closing the follower fd */
	while (recv(fd, &cmd, sizeof(cmd), MSG_WAITALL) == -1) {
		if (errno != EINTR && errno != EAGAIN) {
			perror("unable to receive message from parent");
			exit(1);
		}
	}
	switch (cmd) {
	case CMD_CONT_FG:
		/* Continue in foreground, grant it controlling tty. */
		if (!tty_initialized) {
			if (term_copy(usertty, follower))
				tty_initialized = true;
		}
		if (tcsetpgrp(follower, child) == -1) {
			/* XXX: debug log? */
		}
		killpg(child, SIGCONT);
		break;
	case CMD_CONT_BG:
		/* Continue in background, I take controlling tty. */
		if (tcsetpgrp(follower, pgrp) == -1) {
			/* XXX: debug log? */
		}
		killpg(child, SIGCONT);
		break;
	default:
		/* unknown command */
		break;
	}
	return 0;
}

static _Noreturn void
exec_monitor(int argc, char *argv[], int usertty, int follower, int backchannel, int fds[3], bool foreground)
{
	struct sigaction action;
	struct pollfd pfds[2] = {0};
	nfds_t nfds = sizeof(pfds)/sizeof(pfds[0]);
	pid_t child;
	pid_t pgrp;
	int status;

	if (!foreground)
		tty_initialized = false;

	/* Start a new session and becomes the leader so we get notified about SIGTSTP */
	if (setsid() == -1) {
		perror("setsid");
		exit(1);
	}
	if (ioctl(follower, TIOCSCTTY, NULL) == -1) {
		perror("unable to set controlling terminal");
		exit(1);
	}

	if (pipe(selfpipe) == -1 ||
	   fcntl(selfpipe[0], F_SETFD, FD_CLOEXEC) == -1 ||
	   fcntl(selfpipe[1], F_SETFD, FD_CLOEXEC) == -1) {
		perror("unable to create pipe");
		exit(1);
	}

	sigemptyset(&action.sa_mask);
	action.sa_handler = sighandler;
	action.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &action, NULL) == -1) {
		perror("unable to setup signal handler");
		exit(1);
	}

	/* Wait until the proxy process notifies us about closing the follower fd */
	while (recv(backchannel, &status, sizeof(status), MSG_WAITALL) == -1) {
		if (errno != EINTR && errno != EAGAIN) {
			perror("unable to receive message from parent");
			exit(1);
		}
	}

	switch ((child = fork())) {
	case -1:
		perror("fork");
		exit(1);
	case 0:
		/* Set command process group here too to avoid a race. */
		setpgid(0, getpid());

		/* Setup standard file descriptors. */
		for (int fd = 0; fd <= 2; fd++) {
			if (fds[fd] == fd)
				continue;
			if (dup2(fds[fd], fd) == -1) {
				perror("dup2");
				exit(1);
			}
		}
		close(backchannel);

		/* Wait for parent to grant us the tty if we are foreground. */
		if (foreground) {
			pid_t self = getpid();
			struct timespec ts = { 0, 1000 };  /* 1us */
			while (tcgetpgrp(follower) != self)
				nanosleep(&ts, NULL);
		}

		close(follower);
		execvp(argv[0], argv);
		exit(1);
	}

	/* Send the command pid */
	while (send(backchannel, &child, sizeof(child), 0) == -1) {
		if (errno != EINTR && errno != EAGAIN) {
			perror("unable to send message to monitor process");
			exit(1);
		}
	}

	pgrp = getpgrp();

	/* Put command in its own process group. */
	setpgid(child, child);

	if (foreground) {
		/* Make the command the foreground process for the pty follower. */
		if (tcsetpgrp(follower, child) == -1) {
			// XXX: debug log?
		}
	}

	pfds[0].fd = selfpipe[0];
	pfds[0].events = POLLIN;
	pfds[1].fd = backchannel;
	pfds[1].events = POLLIN|POLLHUP|POLLERR;
	for (;;) {
		if (poll(pfds, nfds, -1) == -1) {
			if (errno != EINTR) {
				perror("poll");
				exit(1);
			}
			continue;
		}
		if (pfds[0].revents & POLLIN) {
			monitor_handle_signal(pfds[0].fd, child, backchannel);
		}
		if (pfds[1].revents & POLLIN) {
			monitor_handle_backchannel(pfds[1].fd, usertty, follower, child, pgrp);
		}
		if (pfds[1].revents & POLLHUP) {
			/* parent died */
			break;
		}
	}

	/*
	 * Take the controlling tty.  This prevents processes spawned by the
	 * command from receiving SIGHUP when the session leader (us) exits.
	 */
	if (tcsetpgrp(follower, getpgrp()) == -1) {
		/* XXX: debug log? */
	}

	while (waitpid(child, &status, 0) == -1) {
		if (errno != EINTR) {
			perror("waitpid");
			exit(1);
		}
	}
	exit(0);
}

static struct winsize cursize;

static int
forward_sync_size(int from, int to)
{
	struct winsize size;
	if (ioctl(from, TIOCGWINSZ, &size) == -1)
		return -1;
	if (memcmp(&cursize, &size, sizeof(cursize)) == 0)
		return 0;
	if (ioctl(to, TIOCSWINSZ, &size) == -1)
		return -1;
	memcpy(&cursize, &size, sizeof(cursize));
	return 0;
}

static int
forward_handle_signal(int fd, int leader, int usertty)
{
	int signo = 0;
	while (read(fd, &signo, sizeof(signo)) == -1) {
		if (errno != EINTR && errno != EAGAIN) {
			perror("unable to read signal");
			exit(1);
		}
	}
	switch (signo) {
	case 0: return 0;
	case SIGWINCH:
		forward_sync_size(usertty, leader);
		return 0;
	case SIGCHLD:
	default:
		/* XXX: Forward signal */
		break;
	}
	return 0;
}

static struct termios oterm;
static bool term_changed;

static bool
term_restore(int fd)
{
	if (tcsetattr_nobg(fd, TCSASOFT|TCSADRAIN, &oterm) != 0)
		return false;
	return true;
}

static bool
term_raw(int fd)
{
	struct termios term;
	if (!term_changed && tcgetattr(fd, &oterm))
		return false;
	memcpy(&term, &oterm, sizeof(term));
	cfmakeraw(&term);
	if (tcsetattr_nobg(fd, TCSASOFT|TCSADRAIN, &term) == 0) {
		term_changed = true;
		return true;
	}
	return false;
}

static enum { TERM_COOKED = 0, TERM_RAW } ttymode = TERM_COOKED;

static int
forward_send_cmd(int fd, enum cmd cmd)
{
	if (cmd == 0)
		return 0;
	while (send(fd, &cmd, sizeof(cmd), 0) == -1) {
		if (errno != EINTR && errno != EAGAIN)
			return -1;
	}
	return 0;
}

static bool foreground = false;

static pid_t
check_foreground(int fd)
{
	pid_t pid = tcgetpgrp(fd);
	if (pid != -1)
		foreground = pid == getpgrp();
	return pid;
}

static bool
forward_resume(int usertty, int leader)
{
	if (check_foreground(usertty) == -1)
		return false;
	if (foreground) {
		/* Foreground process, set tty to raw mode. */
		if (!tty_initialized) {
			if (term_copy(usertty, leader) == 0)
				tty_initialized = true;
		}
		if (term_raw(usertty))
			ttymode = TERM_RAW;
	} else {
		/* Background process, no access to tty. */
		ttymode = TERM_COOKED;
	}
	forward_sync_size(usertty, leader);
	return true;
}

static enum cmd
forward_suspend(int signo, int usertty, int leader)
{
	struct sigaction sa = {0}, osa, osa_sigcont;
	pid_t ppgrp;
	enum cmd ret = 0;

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	sa.sa_handler = SIG_IGN;
	if (sigaction(SIGCONT, &sa, &osa_sigcont) != 0)
		perror("unable to set handler for SIGCONT");

	switch (signo) {
	case SIGTTOU: /* fallthrough */
	case SIGTTIN:
		/*
		 * If parent is already the foreground process, just resume the command
		 * in the foreground.  If not, we'll suspend sudo and resume later.
		 */
		if (!foreground) {
			if (check_foreground(usertty) == -1) {
				/* User's tty was revoked. */
				break;
			}
		}
		if (foreground) {
			if (ttymode != TERM_RAW) {
				if (term_raw(usertty) == 0)
					ttymode = TERM_RAW;
				/* Resume command in foreground */
				return CMD_CONT_FG;
			}
		}
		/* fallthrough */
	case SIGSTOP: /* fallthrough */
	case SIGTSTP: /* fallthrough */
	default:
		if (ttymode != TERM_COOKED) {
			if (!term_restore(usertty))
				perror("unable to restore terminal settings");
			else
				ttymode = TERM_COOKED;
		}
		if (signo != SIGSTOP) {
			sigemptyset(&sa.sa_mask);
			sa.sa_handler = SIG_DFL;
			sa.sa_flags = SA_RESTART;
			if (sigaction(signo, &sa, NULL) == -1)
				perror("unable to set handler for SIGTSTP");
		}
		ppgrp = getpgrp();
		if ((ppgrp != getpid() && kill(ppgrp, 0) == -1) || killpg(ppgrp, signo) == -1) {
			perror("no parent to suspend, terminating command.");
			/* XXX: actually terminate */
		}
		/* Continue */
		if (signo != SIGSTOP) {
			if (sigaction(signo, &osa, NULL) == -1)
				perror("unable to restore handler for SIGTSTP");
		}
		if (!forward_resume(usertty, leader))
			return 0;
		return ttymode == TERM_RAW ? CMD_CONT_FG : CMD_CONT_BG;
	}
	if (sigaction(SIGCONT, &osa_sigcont, NULL) == -1)
		perror("unable to restore handler for SIGCONT");
	return 0;
}

static int
forward_recv_status(int fd, int *statusp)
{
	while (recv(fd, statusp, sizeof(*statusp), MSG_WAITALL) == -1) {
		if (errno != EINTR && errno != EAGAIN)
			return -1;
	}
	return 0;
}

static int
forward_read(struct pollfd *from, struct pollfd *to, char *buf, size_t bufsz, size_t *buflen)
{
	struct sigaction sa = {0}, osa;
	ssize_t rd;
	int saved_errno;

	sigemptyset(&sa.sa_mask);
	sa.sa_handler = sigttin;
	got_sigttin = 0;
	sigaction(SIGTTIN, &sa, &osa);
	rd = read(from->fd, buf + *buflen, bufsz - *buflen);
	saved_errno = errno;
	sigaction(SIGTTIN, &osa, NULL);
	errno = saved_errno;

	if (rd == -1) {
		if (errno == EINTR && got_sigttin) {
		}
		if (errno == EAGAIN)
			return 0;
		return -1;
	} else if (rd == 0) {
	} else {
		*buflen += rd;
		if (*buflen > 0) {
			if (*buflen == bufsz)
				from->events &= ~POLLIN;
			to->events |= POLLOUT;
			/* try a write if have new data */
			to->revents |= POLLOUT;
		}
	}
	return 0;
}

static int
forward_write(struct pollfd *from, struct pollfd *to, char *buf, size_t bufsz, size_t *buflen)
{
	ssize_t wr = write(to->fd, buf, *buflen);
	if (wr == -1) {
		if (errno != EINTR && errno != EAGAIN)
			return -1;
		return 0;
	}
	memmove(buf, buf + wr, *buflen - wr);
	*buflen -= wr;
	if (*buflen < bufsz) {
		from->events |= POLLIN;
		if (*buflen == 0)
			to->events &= ~POLLOUT;
	}
	return 0;
}

static int
forward_proxy(struct pollfd *from, struct pollfd *to, char *buf, size_t bufsz, size_t *buflen)
{
	if (from->revents & POLLIN) {
		if (forward_read(from, to, buf, bufsz, buflen) == -1)
			return -1;
	}
	if (to->revents & POLLOUT) {
		if (forward_write(from, to, buf, bufsz, buflen) == -1)
			return -1;
	}
	return 0;
}

static _Noreturn void
forward(int backchannel, int leader, int usertty, pid_t monitor)
{
	char inbuf[2048];
	char oubuf[2048];
	struct pollfd pfds[4] = {0};
	nfds_t nfds = sizeof(pfds)/sizeof(pfds[0]);
	size_t inlen = 0;
	size_t oulen = 0;
	int status = 0;
	int rc = 0;
	pid_t cmdpid = -1;

	/* Receive the command pid */
	while (recv(backchannel, &cmdpid, sizeof(cmdpid), MSG_WAITALL) == -1) {
		if (errno != EINTR && errno != EAGAIN) {
			perror("unable to receive message from parent");
			exit(1);
		}
	}

	pfds[0].fd = selfpipe[0];
	pfds[0].events = POLLIN;
	pfds[1].fd = backchannel;
	pfds[1].events = POLLIN|POLLHUP|POLLERR;
	pfds[2].fd = usertty;
	pfds[2].events = POLLIN|POLLHUP|POLLERR;
	pfds[3].fd = leader;
	pfds[3].events = POLLIN|POLLHUP|POLLERR;
	if (foreground) {
		pfds[2].events |= POLLIN;
		pfds[3].events |= POLLIN;
	}
	while (cmdpid != -1) {
		if (poll(pfds, nfds, -1) == -1) {
			if (errno != EINTR) {
				perror("poll");
				exit(1);
			}
			continue;
		}
		/* Handle signals */
		if (pfds[0].revents & POLLIN) {
			forward_handle_signal(pfds[0].fd, leader, usertty);
		}
		/* Handle waitpid status from monitor */
		if (pfds[1].revents & POLLIN) {
			if (forward_recv_status(backchannel, &status) == 0) {
				if (WIFEXITED(status) || WIFSIGNALED(status)) {
					cmdpid = -1;
					break;
				}
				if (WIFSTOPPED(status)) {
					/* Suspend parent and tell monitor how to resume on return. */
					int signo = WSTOPSIG(status);
					enum cmd cmd = forward_suspend(signo, usertty, leader);
					forward_send_cmd(backchannel, cmd);
					if (foreground) {
						pfds[2].events |= POLLIN;
						pfds[3].events |= POLLIN;
					}
				}
			}
		}
		if (foreground) {
			/* Proxy from usertty to leader */
			if (forward_proxy(&pfds[2], &pfds[3], inbuf, sizeof(inbuf), &inlen) == -1)
				break;
			/* Proxy from leader to usertty */
			if (forward_proxy(&pfds[3], &pfds[2], oubuf, sizeof(oubuf), &oulen) == -1)
				break;
		} else {
			/* XXX: SIGTTOU SIGTTIN?? */
		}
	}

	/* Restore original terminal configuration before exiting/printing status */
	if (tcsetattr_nobg(usertty, TCSASOFT|TCSADRAIN, &oterm) != 0) {
		perror("tcsetattr");
	}

	if (WIFEXITED(status)) {
		rc = WEXITSTATUS(status);
	} else if (WIFSIGNALED(status)) {
		fprintf(stderr, "%s%s\n", strsignal(WTERMSIG(status)),
				WCOREDUMP(status) ? " (core dumped)" : "");
		rc = WTERMSIG(status) + 128;
	} else {
		rc = 0;
		/* this shouldn't happen */
	}

	exit(rc);
}

int
main(int argc, char *argv[])
{
	struct sigaction action;
	struct stat st;
	bool pipeline = false;
	int fds[3] = {-1, -1, -1};
	int sv[2];
	int usertty;
	int leader;
	int follower;
	int status;
	pid_t monitor;

	if (argc < 2) {
		fprintf(stderr, "usage: %s command [args]\n", argc > 0 ? argv[0] : "runpty");
		exit(1);
	}
	argc -= 1;
	argv += 1;

	if (pipe(selfpipe) == -1 ||
	   fcntl(selfpipe[0], F_SETFD, FD_CLOEXEC) == -1 ||
	   fcntl(selfpipe[1], F_SETFD, FD_CLOEXEC) == -1) {
		perror("unable to create pipe");
		exit(1);
	}

	if (socketpair(PF_UNIX, SOCK_STREAM, 0, sv) == -1 ||
	    fcntl(sv[0], F_SETFD, FD_CLOEXEC) == -1 ||
	    fcntl(sv[1], F_SETFD, FD_CLOEXEC) == -1) {
		perror("unable to create socket pair");
		exit(1);
	}

	usertty = open(_PATH_TTY, O_RDWR|O_CLOEXEC);
	if (usertty == -1) {
		perror("unable to open controlling terminal");
		exit(1);
	}
	fcntl(usertty, F_SETFL, O_NONBLOCK);

	if (openpty(&leader, &follower, NULL, NULL, NULL) == -1) {
		perror("unable to open new pty");
		exit(1);
	}
	fcntl(leader, F_SETFL, O_NONBLOCK);

	foreground = tcgetpgrp(usertty) == getpgrp();
	if (term_copy(usertty, leader) == -1) {
		perror("unable to copy terminal settings to pty");
		exit(1);
	}
	if (foreground) {
		if (!pipeline && term_raw(usertty))
			ttymode = TERM_RAW;
		tty_initialized = true;
	}

	sigemptyset(&action.sa_mask);
	action.sa_handler = sighandler;
	action.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &action, NULL) == -1 ||
	    sigaction(SIGWINCH, &action, NULL) == -1) {
		perror("unable to setup signal handler");
		exit(1);
	}

	/* Setup the standard file descriptor for the command:
	 * If our fd is a tty then it is set to the pty, otherwise
	 * just pass the filedescriptor through.
	 */
	for (int fd = 0; fd <= 2; fd++) {
		/* if the file descriptor is a tty, the pty is used */
		if (isatty(fd) == 1) {
			fds[fd] = follower;
		} else {
			if (fstat(fd, &st) == 0 && S_ISFIFO(st.st_mode))
				pipeline = true;
			fds[fd] = fd;
		}
	}

	switch ((monitor = fork())) {
	case -1:
		perror("fork");
		exit(1);
	case 0:
		close(leader);
		close(selfpipe[0]);
		close(selfpipe[1]);
		close(sv[0]);
		exec_monitor(argc, argv, usertty, follower, sv[1], fds, foreground);
		/* unreachable */
	}
	close(sv[1]);

	close(follower);

	/* Tell the monitor to continue now that the follower is closed. */
	status = 0;
	while (send(sv[0], &status, sizeof(status), 0) == -1) {
		if (errno != EINTR && errno != EAGAIN) {
			perror("unable to send message to monitor process");
			exit(1);
		}
	}

	forward(sv[0], leader, usertty, monitor);
}
