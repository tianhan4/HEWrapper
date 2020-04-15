-include make/env.mk

.PHONY: all lib clean

all:
	make clean
	make lib

lib:
	$(MAKE) -C src
	@mv src/$(HW_LIB) .

clean:
	rm -f $(HW_LIB)
	$(MAKE) -C src clean
