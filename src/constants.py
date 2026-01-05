from enum import IntEnum

class PESignature(IntEnum):
    """
    Constants for PE file signatures (Magic Numbers).
    Documentation: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
    """
    # 'MZ' - Mark Zbikowski (Design of DOS). Found at offset 0.
    DOZ_HEADER = 0x5A4D  
    
    # 'PE\0\0' - Portable Executable Signature.
    NT_HEADER = 0x00004550 

class PEOffsets(IntEnum):
    """
    Fixed offsets within standard headers.
    """
    # At offset 0x3C (60 bytes) inside the DOS Header, 
    # there is a 4-byte integer pointing to the PE Header.
    E_LFANEW = 0x3C

class MachineType(IntEnum):
    """
    Machine architecture identifiers.
    """
    IMAGE_FILE_MACHINE_I386 = 0x014c  # x86 (32-bit)
    IMAGE_FILE_MACHINE_AMD64 = 0x8664 # x64 (64-bit)

class OptionalHeaderMagic(IntEnum):
    """
    Magic numbers for the Optional Header.
    Determines if the PE is PE32 (32-bit) or PE32+ (64-bit).
    """
    PE32 = 0x10b      # 32-bit executable
    PE32_PLUS = 0x20b # 64-bit executable

class SectionFlags(IntEnum):
    """
    Characteristics flags for PE Sections.
    """
    CNT_CODE = 0x00000020                # Contains executable code
    CNT_INITIALIZED_DATA = 0x00000040    # Contains initialized data
    CNT_UNINITIALIZED_DATA = 0x00000080  # Contains uninitialized data
    MEM_EXECUTE = 0x20000000             # Section is executable (Bit 29)
    MEM_READ = 0x40000000                # Section is readable (Bit 30)
    MEM_WRITE = 0x80000000               # Section is writeable (Bit 31)