CC = $(CROSS_COMPILE)gcc

CFLAGS = -O0 -Werror -Wall -ggdb
CPPFLAGS = -I. -I../../include

ifdef KERNEL_DIR
CPPFLAGS += -I$(KERNEL_DIR)/arch/powerpc/include
endif

OBJS = opal-prd.o thunk.o

opal-prd: $(OBJS)
	$(LINK.o) -o $@ $^

all: opal-prd

.PHONY: links
links:
	ln -sf ../../ccan .

$(OBJS): links

clean:
	rm -f *.[odsa] opal-prd

distclean: clean
	rm -f *~
