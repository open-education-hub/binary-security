CFLAGS = -Wall -m32
LDFLAGS = -m32
LDLIBS = -lpthread
SKEL_BASE = ../../../skel

.PHONY: all clean

all: crackme6

deploy:
	cp crackme6 $(SKEL_BASE)/crackmes/crackme6/

clean:
	-rm -f crackme6
