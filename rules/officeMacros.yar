rule OfficeWithMacros {
    meta: 
        description = "Detects Office files with macros"
    strings:
        $ole_header = { D0 CF 11 E0 } // OLE2 header
        $macro_stream = { 00 00 00 00 } // Placeholder for macro
    condition:
        uint32(0) == 0xD0CF11E0 and // "D0 CF 11 E0" - OLE2 header
        uint16(0x3C) == 0x0000 and // Check for the presence of a macro stream
        uint32(0x4C) == 0x00000000 // Check for the presence of a macro
}