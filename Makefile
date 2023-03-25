CFLAGS?=-g -O2 -Wall -Wextra -pedantic

all: runpty

runpty: runpty.o

clean:
	rm -f runpty runpty.o

README: runpty.1
	mandoc -Tutf8 $< | col -bx >$@
