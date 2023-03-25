CFLAGS?=-std=c99 -g -O2 -Wall -Wextra -pedantic

PREFIX?=/usr/local
BINDIR?=${PREFIX}/bin
MANDIR?=${PREFIX}/share/man

all: runpty

runpty: runpty.o

clean:
	rm -f runpty runpty.o

README: runpty.1
	mandoc -Tutf8 $< | col -bx >$@

install: runpty
	mkdir -p -m 0755 ${DESTDIR}${BINDIR}
	mkdir -p -m 0755 ${DESTDIR}${MANDIR}/man1
	cp -f runpty ${DESTDIR}${BINDIR}
	cp -f runpty.1 ${DESTDIR}${MANDIR}/man1
