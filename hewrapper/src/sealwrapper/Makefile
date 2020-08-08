-include ../../make/env.mk
.PHONY: all build clean_seal clean

SEAL_DIR := ../../../third_party/seal/native/src
CUR_DIR := $(shell pwd)

INCLUDE_DIR := -I./include/SEAL-$(SEAL_VER) -I../../include
CFLAGS := -Wall -O2 -fPIC -std=c++17 

all: build

build: clean lib/libseal.a
	$(CC) $(CFLAGS) $(INCLUDE_DIR) -c -o sealengine.o SEALEngine.cpp
	$(CC) $(CFLAGS) $(INCLUDE_DIR) -c -o sealhe.o SEALHE.cpp
	
lib/libseal.a:
	@cd $(SEAL_DIR); cmake . -DCMAKE_INSTALL_PREFIX=$(CUR_DIR); make -j4; make install
	mv lib/libseal-$(SEAL_VER).a lib/libseal.a

clean:
	rm -f *.o

clean_seal:
	rm -rf include lib
