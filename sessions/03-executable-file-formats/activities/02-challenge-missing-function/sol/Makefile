all: solve

solve: libstuff.so
	LD_LIBRARY_PATH=. ../src/helpless-binary

libstuff.so: stuff.c
	gcc -m32 -shared -o $@ $<

clean:
	rm -f *.so

.PHONY: all clean
