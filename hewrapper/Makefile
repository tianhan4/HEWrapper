-include make/env.mk

.PHONY: all clean test

all:
	make clean
	make lib
	make test

lib: $(HW_LIB)

$(HW_LIB):
	$(MAKE) -C src
	@mv src/$(HW_LIB) .

clean:
	rm -f $(HW_LIB)
	$(MAKE) -C src clean
	$(MAKE) -C test clean

test: lib
	$(MAKE) -C test
	@mv test/seal_test .
