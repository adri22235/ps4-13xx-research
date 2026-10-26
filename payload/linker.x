OUTPUT_FORMAT("elf64-x86-64", "elf64-x86-64", "elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

PHDRS
{
	text PT_LOAD FLAGS(5); /* R+X */
	data PT_LOAD FLAGS(6); /* R+W */
}

SECTIONS
{
	. = 0;
	.text : {
		*(.text.entry)
		*(.text*)
	} : text

	.rodata : {
		*(.rodata*)
	} : text

	.data : {
		*(.data*)
	} : data

	.bss : {
		*(.bss*)
	} : data
}
