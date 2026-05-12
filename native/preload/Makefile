# Makefile for libdotnope_preload.so
# LD_PRELOAD library for libc getenv interposition

CC ?= gcc
CFLAGS = -Wall -Wextra -fPIC -O2 -D_GNU_SOURCE
LDFLAGS = -shared -ldl -lpthread

TARGET = libdotnope_preload.so
SRC = dotnope_preload.c

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -D -m 755 $(TARGET) /usr/local/lib/$(TARGET)
	@echo "Installed to /usr/local/lib/$(TARGET)"
	@echo ""
	@echo "Usage:"
	@echo "  LD_PRELOAD=/usr/local/lib/$(TARGET) node app.js"
	@echo ""
	@echo "Configuration:"
	@echo "  DOTNOPE_POLICY=package=VAR1|VAR2;other-package=*"
	@echo "  DOTNOPE_LOG=1|stderr|/path  (enable logging)"
