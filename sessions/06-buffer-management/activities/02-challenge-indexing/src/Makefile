all: indexing

indexing: indexing.c
	gcc -m32 -fno-stack-protector -mpreferred-stack-boundary=2 -o $@ $<

clean:
	rm -f indexing
