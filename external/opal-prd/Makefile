CC = $(CROSS_COMPILE)gcc

CFLAGS = -m64 -Werror -Wall -g2 -ggdb
LDFLAGS = -m64
ASFLAGS = -m64
CPPFLAGS = -I. -I../../include

# Use make V=1 for a verbose build.
ifndef V
        Q_CC=	@echo '    CC ' $@;
        Q_LINK=	@echo '  LINK ' $@;
        Q_LN=   @echo '    LN ' $@;
endif

OBJS = opal-prd.o thunk.o pnor.o i2c.o libflash/libffs.o libflash/libflash.o

all: opal-prd

.PHONY: links
links:
	mkdir -p libflash asm
	$(Q_LN)ln -sfr ../../libflash/*.h libflash/
	$(Q_LN)ln -sfr ../../libflash/*.c libflash/
	$(Q_LN)ln -sfr ../../ccan .
ifdef KERNEL_DIR
	$(Q_LN)ln -sfr $(KERNEL_DIR)/arch/powerpc/include/uapi/asm/opal-prd.h asm/
endif

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
	$(RM) *.[odsa] libflash/*.[odsa] opal-prd
	$(RM) test/*.[odsa] test/test_pnor

distclean: clean
	$(RM) -f *~ ccan
	$(RM) -rf libflash asm
