-include ../../make/env.mk
.PHONY: all build clean_seal clean

SEAL_DIR := ../../../third_party/seal
BOOST_DIR = ./include/boost_1_75_0
SEAL_INCLUDE_DIR := ./include/SEAL-${SEAL_VER}
CUR_DIR := $(shell pwd)

INCLUDE_DIR := -I${BOOST_DIR} -I${SEAL_INCLUDE_DIR} -I../../include
CFLAGS := -g -Wall -O2 -fPIC -std=c++17 -DBOOST_ASIO_SEPARATE_COMPILATION 

all: clean build

build: lib/libseal.a
	$(CC) $(CFLAGS) $(INCLUDE_DIR) -c -o sealengine.o SEALEngine.cpp
	$(CC) $(CFLAGS) $(INCLUDE_DIR) -c -o sealhe.o SEALHE.cpp
	$(CC) $(CFLAGS) $(INCLUDE_DIR) -c -o ciphertextwrapper.o CiphertextWrapper.cpp
	$(CC) $(CFLAGS) $(INCLUDE_DIR) -c -o netio.o NetIO.cpp


lib/libseal.a:
	@cd $(SEAL_DIR); make clean; cmake . -DCMAKE_INSTALL_PREFIX=$(CUR_DIR); make -j4;  make install
	#@cd $(SEAL_DIR); cmake . -DCMAKE_INSTALL_PREFIX=$(CUR_DIR); make -j4; make install
	mv lib/libseal-$(SEAL_VER).a lib/libseal.a

clean:
	rm -f *.o

clean_seal:
	rm -rf include lib
