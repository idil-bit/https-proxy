src = $(wildcard *.c)
obj = $(src:.c=.o)
CC = gcc
CFLAGS = -Wall -Wextra -g 

UNAME := $(shell uname)
LDFLAGS = -L/usr/lib -lssl -lcrypto

ifeq ($(UNAME), Linux)
    LDFLAGS += -lnsl
	CFLAGS += -I/usr/include/openssl
else ifeq ($(UNAME), Darwin)  # Check for macOS
    OPENSSL_DIR := $(shell brew --prefix openssl@3)
    CFLAGS += -I$(OPENSSL_DIR)/include
    LDFLAGS += -L$(OPENSSL_DIR)/lib -lssl -lcrypto
endif


a.out: $(obj)
	$(CC) -o $@ $^ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(obj) a.out
