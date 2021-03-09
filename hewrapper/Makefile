-include make/env.mk

.PHONY: all clean test

all:
	make clean
	make lib
	make seal_test

lib: $(HW_LIB)

$(HW_LIB):
	$(MAKE) -C src
	@mv src/$(HW_LIB) .
	@mv src/netio.o .

clean:
	rm -f $(HW_LIB)
	rm -f netio.o
	$(MAKE) -C src clean
	$(MAKE) -C test clean

seal_test: $(HW_LIB)
	$(MAKE) -C test
	@mv test/seal_test .
