SDK=$(shell xcrun --sdk iphoneos --show-sdk-path 2>/dev/null)
CC=clang
ARCH=-arch arm64e
MIN_VER=-miphoneos-version-min=17.0
SYSROOT=-isysroot $(SDK)
CFLAGS=$(ARCH) $(MIN_VER) $(SYSROOT) -O2 -Wall -Wextra -Werror=implicit-function-declaration
LDFLAGS=-dynamiclib -Wl,-exported_symbol,_start -Wl,-exported_symbol,_startl \
        -Wl,-exported_symbol,_startr -Wl,-exported_symbol,_startm \
        -framework CoreFoundation -lSystem

TARGET=coruna_cve_test.dylib
SRC=coruna_cve_test.c

.PHONY: all clean check

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	@echo "--- Build info ---"
	@file $@
	@nm -gU $@ | grep " T "
	@echo "--- Size ---"
	@ls -la $@

check: $(TARGET)
	@echo "=== Verifying exports match type 0x08 interface ==="
	@nm -gU $(TARGET) | grep -q "_start$$" && echo "OK: _start" || echo "MISSING: _start"
	@nm -gU $(TARGET) | grep -q "_startl$$" && echo "OK: _startl" || echo "MISSING: _startl"
	@nm -gU $(TARGET) | grep -q "_startr$$" && echo "OK: _startr" || echo "MISSING: _startr"
	@nm -gU $(TARGET) | grep -q "_startm$$" && echo "OK: _startm" || echo "MISSING: _startm"
	@echo "=== Verifying arm64e ==="
	@file $(TARGET) | grep -q "arm64e" && echo "OK: arm64e" || echo "FAIL: wrong arch"
	@echo "=== Verifying dylib ==="
	@file $(TARGET) | grep -q "dynamically linked shared library" && echo "OK: dylib" || echo "FAIL: not dylib"
	@echo "=== Original type 0x08 exports (reference) ==="
	@nm -gU ../../Archive/coruna/payloads/377bed7460f7538f96bbad7bdc2b8294bdc54599/entry0_type0x08.dylib 2>/dev/null || echo "(original not found for comparison)"

clean:
	rm -f $(TARGET)
