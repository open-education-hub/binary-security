CFLAGS = -m32 -fno-stack-protector -Wall -Wno-format-security
LDFLAGS = -no-pie
CC = gcc

.PHONY: build check_binary check_port

build:
	$(CC) $(CFLAGS) $(LDFLAGS) rwslotmachine3.c -o rwslotmachine3

check_binary:
	[ -f rwslotmachine3 ] && chmod +x rwslotmachine3 \
	|| echo "error: executable file not found"

check_port:
	if ss -tulnp | grep 31346 | grep -q ld-linux.so.2; then \
		echo "executable listens or operates on port 31346."; \
	else \
		echo "error: executable doesn't operate on port 31346."; \
	fi
