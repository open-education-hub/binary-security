CFLAGS = -Wall -g

.PHONY: all clean deploy

all: deploy

deploy: broken
	strip broken

broken: broken.o

broken.o: broken.c

clean:
	-rm -f *~
	-rm -f broken.o
