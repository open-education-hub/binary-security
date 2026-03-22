CC = gcc
CFLAGS = -Wall -Wextra -O2

TARGET = rwslotmachine1
SRC = rwslotmachine1.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)
