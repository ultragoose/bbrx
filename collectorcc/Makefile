TARGET = collectorCC
LIBS = -lmnl
CC = gcc
CFLAGS = -g -Wall -DGET_BBRX_INFO
#CFLAGS = -g -Wall -D_CUSTOM_DIAG_HEADER__ -DGET_BBRX_INFO

.PHONY: default all clean

default: $(TARGET)
all: default

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
HEADERS = $(wildcard *.h)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -Wall $(LIBS) -o $@

clean:
	-rm -f *.o
	-rm -f $(TARGET)
