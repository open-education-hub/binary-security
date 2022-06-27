CFLAGS = -Wall -m32 -no-pie
LDFLAGS = -m32
SKEL_BASE = ../../../skel

.PHONY: all clean

all: crackme3

deploy:
	cp crackme3 $(SKEL_BASE)/crackmes/crackme3/

clean:
	-rm -f crackme3
