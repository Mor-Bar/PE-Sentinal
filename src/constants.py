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