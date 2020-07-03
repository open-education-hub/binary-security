all: helpless-binary

helpless-binary: help.c libstuff.so
	gcc -m32 -L. -lstuff -o $@ $<

libstuff.so: stuff.c
	gcc -m32 -shared -o $@ $<

clean:
	rm -f helpless-binary *.so *.o

.PHONY: all clean
