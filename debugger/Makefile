# Directories
LIBPS4 := ../ps4-payload-sdk
ODIR   := build
SDIR   := source

# Addresses
TEXT   := 0x926200000
DATA   := 0x926300000

# Include and Library Directories
IDIRS   := -I$(LIBPS4)/include -I. -Iinclude
LDIRS   := -L$(LIBPS4) -L. -Llib

# Compiler and Linker Flags
CFLAGS  := $(IDIRS) -O2 -std=c11 -fno-builtin -nostartfiles -nostdlib -Wall -masm=intel -march=btver2 -mtune=btver2 -m64 -mabi=sysv \
            -mcmodel=large -DTEXT_ADDRESS=$(TEXT) -DDATA_ADDRESS=$(DATA)

SFLAGS   := -nostartfiles -nostdlib -march=btver2 -mtune=btver2
LFLAGS   := $(LDIRS) -Xlinker -T $(LIBPS4)/linker.x -Wl,--build-id=none -Ttext=$(TEXT) -Tdata=$(DATA)

# Source Files
CFILES   := $(wildcard $(SDIR)/*.c)
SFILES   := $(wildcard $(SDIR)/*.s)
OBJS     := $(patsubst $(SDIR)/%.c, $(ODIR)/%.o, $(CFILES)) \
            $(patsubst $(SDIR)/%.s, $(ODIR)/%.o, $(SFILES))

LIBS     := -lPS4
TARGET   := debugger.bin

# Build Target
$(TARGET): $(OBJS) | $(ODIR)
	@echo "Linking objects to create $(TARGET)..."
	@gcc $(LIBPS4)/crt0.s $(OBJS) -o temp.t $(CFLAGS) $(LFLAGS) $(LIBS)
	@echo "Creating binary file $(TARGET)..."
	@objcopy -O binary temp.t $(TARGET)
	@echo "Cleaning up temporary files..."
	@rm -f temp.t

# Compile C files
$(ODIR)/%.o: $(SDIR)/%.c
	@echo "Compiling C source $<..."
	@gcc -c -o $@ $< $(CFLAGS)

# Compile Assembly files
$(ODIR)/%.o: $(SDIR)/%.s
	@echo "Assembling source $<..."
	@gcc -c -o $@ $< $(SFLAGS)

# Create output directory
$(ODIR):
	@echo "Creating output directory $(ODIR)..."
	@mkdir -p $@

# Clean target
.PHONY: clean
clean:
	@echo "Cleaning up build artifacts..."
	@rm -f $(TARGET) $(ODIR)/*.o