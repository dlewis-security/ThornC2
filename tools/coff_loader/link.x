/*  link.x — COFF loader linker script
 *
 *  Guarantees loader_entry is the first byte of .text so that the
 *  PE section extractor produces a blob whose entry point is at offset 0.
 *
 *  .bss is discarded — all mutable globals use explicit non-zero .data
 *  initializers so they appear in the file with raw data.  This avoids
 *  the issue where bss sections have no raw data pointer in the PE file,
 *  which would cause the stub extractor to read wrong bytes.
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

    /DISCARD/ : {
        *(.bss .bss.*)
        *(COMMON)
        *(.pdata)
        *(.xdata)
        *(.reloc)
        *(.idata .idata.*)
        *(.tls  .tls.*)
        *(.edata)
        *(.debug*)
    }
}
