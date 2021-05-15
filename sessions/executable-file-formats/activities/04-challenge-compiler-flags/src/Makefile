CFLAGS_PIC = -m32 -fPIC
CFLAGS_NOPIC = -m32 -fno-PIC
LDFLAGS_PIE = -m32 -pie
LDFLAGS_NOPIE = -m32 -no-pie

.PHONY: all clean

all: caller-pie caller-no-pie

caller-pie: caller1.o flag1.o
	$(CC) $(LDFLAGS_PIE) -o $@ $^

caller1.o: caller.c
	$(CC) $(CFLAGS_PIC) -c -o $@ $<

flag1.o: flag.c
	$(CC) $(CFLAGS_PIC) -c -o $@ $<

caller-no-pie: caller2.o flag2.o
	$(CC) $(LDFLAGS_NOPIE) -o $@ $^

caller2.o: caller.c
	$(CC) $(CFLAGS_NOPIC) -c -o $@ $<

flag2.o: flag.c
	$(CC) $(CFLAGS_NOPIC) -c -o $@ $<

clean:
	-rm -f *~
	-rm -f *.o
	-rm -f caller-pie caller-no-pie
