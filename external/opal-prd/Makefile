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

OBJS = opal-prd.o thunk.o

.PHONY: links
links:
	ln -sf ../../ccan .

$(OBJS): links

all: opal-prd

%.o: %.c
	$(Q_CC)$(COMPILE.c) $< -o $@

%.o: %.S
	$(Q_CC)$(COMPILE.S) $< -o $@

opal-prd: $(OBJS)
	$(Q_LINK)$(LINK.o) -o $@ $^

clean:
	$(RM) *.[odsa] opal-prd

distclean: clean
	$(RM) -f *~
