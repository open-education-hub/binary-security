CFLAGS = -Wall -m32 -O0
LDFLAGS = -m32

TOOLS=emperor wrong
BIN_TOOLS=$(addsuffix .o, $(TOOLS))

all: $(TOOLS) $(STRIPPED_TOOLS)

emperor: emperor.o
emperor.o: emperor.c
	$(CC) $(CFLAGS) -g -c $< -o $@

wrong: wrong.o
	$(CC) $(CFLAGS) $< -o $@
	-strip $@

.PHONY: clean
clean:
	-rm -f $(TOOLS) $(BIN_TOOLS)
