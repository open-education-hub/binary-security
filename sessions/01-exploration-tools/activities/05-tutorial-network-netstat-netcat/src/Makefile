CFLAGS = -Wall -m32
LDFLAGS = -Wall -m32
LDLIBS = -lnsl
SRV = server
CLT = client
SKEL_BASE = ../../../skel

.PHONY: all start

all: $(SRV) $(CLT)

start: $(SRV)
	@./$(SRV) 31337

$(SRV): $(SRV).o

$(SRV).o: $(SRV).c

$(CLT): $(CLT).o

$(CLT): $(CLT).o

deploy:
	cp $(SRV) $(CLT) $(SKEL_BASE)/crackmes/crackme5/

clean:
	-rm -f $(SRV) $(CLT)
	-rm -f *.o
