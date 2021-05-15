CFLAGS=-fno-PIC -m32

all: p1 p2 p3 p4

p1: main.c
	gcc $(CFLAGS) -c -o $@ $<

p2: second.c
	gcc $(CFLAGS) -c -o $@ $<

p3: third.c
	gcc $(CFLAGS) -c -o $@ $<

p4: libguess.c
	gcc $(CFLAGS) -c -o $@ $<

clean:
	rm -f p1 p2 p3 p4 puzzle

.PHONY: all clean
