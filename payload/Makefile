CC      := gcc
OBJCOPY := objcopy
CFLAGS  := -Os -std=gnu11 -masm=intel -march=btver2 -m64 -mabi=sysv -mcmodel=small \
           -fPIE -fno-stack-protector -fno-builtin -nostdlib -Wall -Wextra
LDFLAGS := -nostdlib -Wl,--build-id=none -T linker.x

TARGET  := kpayload_stage1_1400

all: $(TARGET).bin $(TARGET).js

$(TARGET).o: $(TARGET).c
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET).elf: $(TARGET).o linker.x
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@

$(TARGET).bin: $(TARGET).elf
	$(OBJCOPY) -j .text -O binary $< $@

$(TARGET).js: $(TARGET).bin
	@echo "[*] Converting $(TARGET).bin to JavaScript payload array..."
	@echo "// PS4 FW 14.00 Stage 1 Ring0 Elevation Payload (Size: $$(wc -c < $<) bytes)" > $@
	@echo "// Developed by Adrián García Casado (@adri22235) - García Casado Security Research" >> $@
	@echo "const KENTRY_STAGE1_1400 = new Uint8Array([" >> $@
	@hexdump -v -e '16/1 "0x%02x, " "\n"' $< | sed 's/0x  ,//g' | sed 's/, $$//' | sed 's/^/    /' >> $@
	@echo "]);" >> $@
	@echo "[+] Generated: $(TARGET).js ($$(wc -c < $<) bytes)"

clean:
	rm -f $(TARGET).o $(TARGET).elf $(TARGET).bin $(TARGET).js

.PHONY: all clean
