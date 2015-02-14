CC = $(CROSS_COMPILE)gcc

CFLAGS = -m64 -Werror -Wall -g2 -ggdb
LDFLAGS = -m64
ASFLAGS = -m64
CPPFLAGS = -I. -I../../include

ifdef KERNEL_DIR
CPPFLAGS += -I$(KERNEL_DIR)/arch/powerpc/include
endif

# Use make V=1 for a verbose build.
ifndef V
        Q_CC=	@echo '    CC ' $@;
        Q_LINK=	@echo '  LINK ' $@;
endif

OBJS = opal-prd.o thunk.o pnor.o libflash/libffs.o libflash/libflash.o

all: opal-prd

.PHONY: links
links:
	ln -sf ../../ccan .
	mkdir -p libflash
	ln -sfr ../../libflash/*.h libflash/
	ln -sfr ../../libflash/*.c libflash/

$(OBJS): links

%.o: %.c
	$(Q_CC)$(COMPILE.c) $< -o $@

%.o: %.S
	$(Q_CC)$(COMPILE.S) $< -o $@

opal-prd: $(OBJS)
	$(Q_LINK)$(LINK.o) -o $@ $^

test: test/test_pnor

test/test_pnor: test/test_pnor.o pnor.o libflash/libflash.o libflash/libffs.o
	$(Q_LINK)$(LINK.o) -o $@ $^

clean:
	$(RM) *.[odsa] opal-prd
	$(RM) test/*.[odsa] test/test_pnor

distclean: clean
	$(RM) -f *~ ccan libflash
