TARGET = rwslotmachine4

all: $(TARGET)

$(TARGET): rwslotmachine4.c
	$(CC) -o $(TARGET) rwslotmachine4.c

clean:
	-rm -f $(TARGET)

.PHONY: all clean
