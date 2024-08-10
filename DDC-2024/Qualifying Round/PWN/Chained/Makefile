CC = gcc
CFLAGS = -ggdb -Wno-implicit-function-declaration

TARGET = chained

all: $(TARGET)

$(TARGET): chained.c
	$(CC) $(CFLAGS) -o $(TARGET) chained.c

clean:
	rm -f $(TARGET)

.PHONY: all clean
