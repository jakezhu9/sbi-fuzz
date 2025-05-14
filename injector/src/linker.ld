/* Define entry point */
ENTRY(_start)

MEMORY
{
    RAM (xrw)  : ORIGIN = 0x80200000, LENGTH = 4M
}

/* Define memory layout */
SECTIONS
{
    /* Text section (code section) */
    .text : {
        *(.text)         /* Place all .text sections here */
        *(.text.*)       /* Match all sections starting with .text */
    } > RAM 

    /* Data section (initialized global variables) */
    .data : {
        *(.data)         /* Place all .data sections here */
        *(.data.*)       /* Match all sections starting with .data */
    } > RAM 

    /* BSS section (uninitialized global variables) */
    .bss : {
        *(.bss)          /* Place all .bss sections here */
        *(.bss.*)        /* Match all sections starting with .bss */
        *(COMMON)        /* Place all COMMON blocks here */
    } > RAM 

    /* Stack definition */
    . = ALIGN(4);         /* Align to 4 bytes */
    _stack_start = .;      /* Stack start address */
    .stack (NOLOAD) : {
        . = . + 0x1000;   /* Allocate 4KB for stack space (adjust size as needed) */
    } > RAM 
    _stack_end = .;        /* Stack end address */
}
