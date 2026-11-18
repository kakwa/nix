CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra
LDFLAGS ?= -static

SRC := poc_embedded.c
BIN := poc-static

.PHONY: all test clean

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

test: $(BIN)
	./$(BIN)

clean:
	rm -f $(BIN) nix-buildpaths-crash.bin
