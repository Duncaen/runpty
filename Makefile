CFLAGS?=-g -O2 -Wall -Wextra -pedantic
all: runpty
runpty: runpty.o
clean:
	rm -f runpty runpty.o
