CC = gcc
CFLAGS = -g -O0 -fPIC
LDFLAGS = -shared

SRCS = ubpf.c
OBJS = $(SRCS:.c=.o)
TARGET = libubpf.so

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean