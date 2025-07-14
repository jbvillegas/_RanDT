rule IsPe {
    meta: 
        description = "Detects Windows PE files (EXE/DLL)"
    condition:
    uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550  // "MZ" + "PE" header
}