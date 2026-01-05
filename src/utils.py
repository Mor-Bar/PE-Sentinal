from src.constants import SectionFlags

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