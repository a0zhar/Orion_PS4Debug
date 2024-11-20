CC	    := gcc
AR	    := ar
ODIR	:= build
SDIR	:= source
IDIR	:= include
CFLAGS	:= -I$(IDIR) -Os -std=c11 -ffunction-sections -fdata-sections -fno-builtin -nostartfiles -nostdlib -Wall -Wextra -masm=intel -march=btver2 -mtune=btver2 -m64 -mabi=sysv -mcmodel=small -fpie -fPIC
CFILES	:= $(wildcard $(SDIR)/*.c)
SFILES	:= $(wildcard $(SDIR)/*.s)
OBJS	:= $(patsubst $(SDIR)/%.c, build/%.o, $(CFILES)) $(patsubst $(SDIR)/%.s, build/%.o, $(SFILES))

TARGET = libPS4.a

$(TARGET): $(ODIR) $(OBJS)
	@$(AR) rcs $@ $(OBJS)

$(ODIR)/%.o: $(SDIR)/%.c
	@echo "Compiling $@"
	@$(CC) -c -o $@ $< $(CFLAGS)

$(ODIR)/%.o: $(SDIR)/%.s
	@echo "Compiling $@"
	@$(CC) -c -o $@ $< $(CFLAGS)

$(ODIR):
	@mkdir $@

.PHONY: clean

clean:
	@echo "Cleaning Up"
	@rm -rf $(TARGET) $(ODIR)