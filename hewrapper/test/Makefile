-include ../make/env.mk
.PHONY: all build clean

BOOST_DIR := ../src/sealwrapper/include/boost_1_75_0
INCLUDE_DIR := -I${BOOST_DIR} -I../include -I../src/sealwrapper -I../src/sealwrapper/include/SEAL-$(SEAL_VER)
LFLAGS := -L../ -l$(HW_LINK) -L../src/sealwrapper/lib -lseal -lpthread -lz
CFLAGS := -Wall -g -O2 -fPIC -std=c++17 -DBOOST_ASIO_SEPARATE_COMPILATION 

all: build

build: 
	$(CC) $(CFLAGS) $(INCLUDE_DIR) -o seal_test seal_test.cpp ../netio.o $(LFLAGS)

clean:
	rm -f *.o seal_test
