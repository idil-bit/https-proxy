# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -Wextra -g

# Libraries
LIBS = -lcurl

# Target executable name
TARGET = example

# Source file
SRC = example.c cJSON.c

# Build the executable
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LIBS)

# Clean up build files
clean:
	rm -f $(TARGET) curled_wikipage.html 

# Phony targets
.PHONY: clean
