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