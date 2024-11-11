src = $(wildcard *.c)
obj = $(src:.c=.o)
CC = gcc
CFLAGS = -Wall -Wextra -g -I/usr/include/openssl
LDFLAGS = -L/usr/lib -lssl -lcrypto -lnsl

a.out: $(obj)
	$(CC) -o $@ $^ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(obj) a.out
