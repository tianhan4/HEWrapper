-include ../make/env.mk

.PHONY: all build

all: build

build:
	$(MAKE) -C sealwrapper
	$(AR) rcs $(HW_LIB) sealwrapper/lib/libseal.a sealwrapper/sealengine.o sealwrapper/sealhe.o sealwrapper/ciphertextwrapper.o
	$(MAKE) -C sealwrapper clean

clean:
	$(MAKE) -C sealwrapper clean
