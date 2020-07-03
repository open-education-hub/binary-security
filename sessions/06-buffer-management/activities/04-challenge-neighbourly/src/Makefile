all: neighbourly

neighbourly: neighbourly.c
	gcc -m32 -fno-stack-protector -mpreferred-stack-boundary=2 -o $@ $<

clean:
	rm -f neighbourly
