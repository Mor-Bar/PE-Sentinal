import hashlib
from src.constants import SectionFlags

def calculate_sha256(file_path: str) -> str:
    """
    Calculates the SHA-256 hash of a file.
    Used for identifying the file in threat intelligence databases (e.g. VirusTotal).
    """
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Read the file in 4K chunks to handle large files efficiently
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def rva_to_offset(rva: int, sections: list) -> int:
    """
    Converts a Relative Virtual Address (RVA) to a raw file offset.
    
    This is critical because data locations in the PE header are defined 
    relative to how they look in memory (Virtual), which is different 
    from how they are stored on disk (Raw).
    
    Args:
        rva (int): The relative virtual address to convert.
        sections (list): A list of dictionaries containing section info.
                         Each dict must have 'VirtualAddr', 'VirtualSize', and 'RawAddr'.
    
    Returns:
        int: The calculated raw file offset, or 0 if parsing fails.
    """
    for section in sections:
        v_addr = section['VirtualAddr']
        v_size = section['VirtualSize']
        raw_addr = section['RawAddr']
        
        # Check if the RVA is inside this section
        if v_addr <= rva < (v_addr + v_size):
            # Calculate the delta (offset inside the section)
            delta = rva - v_addr
            return raw_addr + delta
            
    # If RVA is not in any section (e.g., inside headers), usually header RVA = Offset
    if rva < 4096: 
        return rva
        
    return 0

def convert_section_characteristics(characteristics: int) -> str:
    """
    Decodes the characteristics flags of a section into a human-readable string.
    
    Args:
        characteristics (int): The raw integer value of the section flags.
        
    Returns:
        str: A string representing permissions (e.g., 'RWX', 'R--', 'RW-').
    """
    perms = []
    
    # Check for Read
    if characteristics & SectionFlags.MEM_READ:
        perms.append("R")
    else:
        perms.append("-")
        
    # Check for Write
    if characteristics & SectionFlags.MEM_WRITE:
        perms.append("W")
    else:
        perms.append("-")
        
    # Check for Execute
    if characteristics & SectionFlags.MEM_EXECUTE:
        perms.append("X")
    else:
        perms.append("-")

    return "".join(perms)