#!/bin/bash

# Directories
LIBPS4="../ps4-payload-sdk"
ODIR="build"
SDIR="."

# Addresses
TEXT="0x926200000"
DATA="0x926300000"

# Tools
CC="gcc"
AS="gcc"
OBJCOPY="objcopy"

# Include and Library Directories
IDIRS="-I$LIBPS4/include -I. -Iinclude"
LDIRS="-L$LIBPS4 -L. -Llib"

# Compiler and Linker Flags
CFLAGS="$IDIRS -O2 -std=c11 -fno-builtin -nostartfiles -nostdlib -Wall -masm=intel -march=btver2 -mtune=btver2 -m64 -mabi=sysv \
        -mcmodel=large -DTEXT_ADDRESS=$TEXT -DDATA_ADDRESS=$DATA"

SFLAGS="-nostartfiles -nostdlib -march=btver2 -mtune=btver2"
LFLAGS="$LDIRS -Xlinker -T $LIBPS4/linker.x -Wl,--build-id=none -Ttext=$TEXT -Tdata=$DATA"

# Output Binary
TARGET="debugger.bin"

# Create output directory
mkdir -p "$ODIR"

# Recursively find .c and .cpp files and compile them to .o files
find "$SDIR" -type f \( -name "*.c" -o -name "*.cpp" \) | while read src_file; do
    # Get the base filename (without the path)
    filename=$(basename "$src_file")
    # Create the corresponding object file path
    obj_file="$ODIR/${filename%.*}.o"
    
    # Check if the file is a .c or .cpp file and compile accordingly
    if [[ "$src_file" == *.c ]]; then
        echo "Compiling C source $src_file..."
        $CC -c -o "$obj_file" "$src_file" $CFLAGS
    elif [[ "$src_file" == *.cpp ]]; then
        echo "Compiling C++ source $src_file..."
        $CC -c -o "$obj_file" "$src_file" $CFLAGS
    fi
done

# Link all .o files to create the final binary
echo "Linking objects to create $TARGET..."
$CC $LIBPS4/crt0.s "$ODIR"/*.o -o temp.t $CFLAGS $LFLAGS -lPS4

# Create binary file
echo "Creating binary file $TARGET..."
$OBJCOPY -O binary temp.t "$TARGET"

# Clean up temporary files
echo "Cleaning up temporary files..."
rm -f temp.t

echo "Build completed successfully."
