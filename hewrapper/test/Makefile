-include ../make/env.mk
.PHONY: all build clean

INCLUDE_DIR := -I../include -I../src/sealwrapper/include/SEAL-$(SEAL_VER)
LFLAGS := -L../ -l$(HW_LINK) -L../src/sealwrapper/lib -lseal -lpthread -lz
CFLAGS := -Wall -O2 -fPIC -std=c++17

all: build

build: clean
	$(CC) $(CFLAGS) $(INCLUDE_DIR) -o seal_test seal_test.cpp $(LFLAGS)

clean:
	rm -f *.o seal_test
