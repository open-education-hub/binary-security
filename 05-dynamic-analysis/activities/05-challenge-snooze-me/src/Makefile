
CC=gcc
CFLAGS=-m32 -fno-stack-protector -no-pie -fno-pic

% :: %.c
	$(CC) $(CFLAGS) $^ -o $@
	strip $@
