/*  link.x — ThornLDR linker script
 *
 *  Guarantees loader_entry is the first byte of .text so that objcopy
 *  --only-section=.text produces a blob whose entry point is at offset 0.
 *
 *  All sections except .text and .data are discarded.  The loader must be
 *  fully position-independent: no absolute relocs, no PE import table.
 */

OUTPUT_FORMAT(pei-x86-64)
ENTRY(loader_entry)

SECTIONS {
    .text : {
        /* entry stub MUST be first */
        *(.text.loader_entry)
        *(.text .text.*)
    }

    .data : {
        *(.data  .data.*)
        *(.rodata .rodata.*)
        *(.rdata  .rdata.*)
    }

    /* discard everything that would pull in absolute addresses or imports */
    /DISCARD/ : {
        *(.pdata)
        *(.xdata)
        *(.reloc)       /* loader itself must have zero base relocations */
        *(.bss .bss.*)
        *(.idata .idata.*)
        *(.tls  .tls.*)
        *(.edata)
        *(.debug*)
    }
}
