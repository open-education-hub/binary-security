all: birds

birds: birds.c
	gcc -m32 -fno-stack-protector -mpreferred-stack-boundary=2 -o $@ $<
	strip birds

clean:
	rm -f birds
