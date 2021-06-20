CFLAGS = -Wall -fno-stack-protector -Wno-unused-but-set-variable -Wno-unused-const-variable

.PHONY: all clean

all: matryoshka do_xor_encrypt

matryoshka: matryoshka.o

matryoshka.o: matryoshka.c

matryoshka.c: matryoshka_template.c inner
	@echo "Generate $@ from $<"
	@msg="$(shell echo -n "{ "; cat inner | hexdump -v -e '"0x" 1/1 "%02x," " "' ; echo "}")"; \
	    sed 's/__TEMPLATE__/'"$$msg"'/' $< > $@

inner: inner.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)
	strip $@

inner.o: inner.c

inner.c: inner_template.c do_xor_encrypt
	@echo "Generate $@ from $<"
	@msg="$(shell cat flag | ./do_xor_encrypt "$(shell cat inner_key)")"; \
	    sed 's/__TEMPLATE__/'"$$msg"'/' $< > $@

do_xor_encrypt: do_xor_encrypt.o

do_xor_encrypt.o: do_xor_encrypt.c

clean:
	-rm -f *~ *.o
	-rm -f matryoshka inner do_xor_encrypt
	-rm -f matryoshka.c inner.c
