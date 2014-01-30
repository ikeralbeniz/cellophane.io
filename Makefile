SHELL = /bin/sh
CC    = gcc
CFLAGS  = -fPIC -shared -Wall -Iinclude -Isrc -lcurl

TARGET  = cellophane.io.so
SOURCES = $(shell echo src/*.c)
OBJECTS = $(SOURCES:.c=.o)


all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS)

install:
	cp include/cellophane_io.h /usr/include/
	cp $(TARGET) /usr/lib/

clean:
	rm -rf *.so
	rm -rf src/*.o