CC = $(CROSS_COMPILE)gcc

CFLAGS = -O0 -Werror -Wall -g2
CPPFLAGS = -I.

ifdef KERNEL_DIR
CPPFLAGS += -I$(KERNEL_DIR)/arch/powerpc/include
endif

opal-prd: opal-prd.o thunk.o
	$(LINK.o) -o $@ $^

all: opal-prd

clean:
	rm -f *.[odsa] opal-prd

distclean: clean
	rm -f *~
