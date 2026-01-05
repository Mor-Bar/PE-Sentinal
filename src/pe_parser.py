import os
import struct
from src.constants import PESignature, PEOffsets

class PEParser:
    """
    A class to parse Windows Portable Executable (PE) files.
    """

    def __init__(self, file_path: str):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"The file '{file_path}' was not found.")
        self.file_path = file_path

    def parse(self):
        """
        Main method to parse the PE file structure.
        Validates DOS Header and parses NT Headers.
        """
        with open(self.file_path, "rb") as f:
            # --- 1. DOS Header Check ---
            dos_sig_data = f.read(2)
            if len(dos_sig_data) < 2:
                raise ValueError("File is too small.")

            dos_sig = struct.unpack("<H", dos_sig_data)[0]
            if dos_sig != PESignature.DOZ_HEADER:
                raise ValueError(f"Invalid DOS Header. Expected MZ, got {hex(dos_sig)}.")

            print(f"[+] Valid DOS Header (MZ) found at offset 0x0.")

            # --- 2. Find the PE Header (e_lfanew) ---
            # Jump to offset 0x3C to read the location of the PE header
            f.seek(PEOffsets.E_LFANEW)
            
            # Read 4 bytes (Unsigned Int -> 'I') representing the offset
            e_lfanew_data = f.read(4)
            pe_offset = struct.unpack("<I", e_lfanew_data)[0]
            
            print(f"[+] e_lfanew pointer found. PE Header is at offset: {hex(pe_offset)}")

            # --- 3. Validate PE Signature ---
            # Jump to the offset we just found
            f.seek(pe_offset)
            
            # Read 4 bytes (The PE Signature)
            pe_sig_data = f.read(4)
            pe_sig = struct.unpack("<I", pe_sig_data)[0]

            if pe_sig != PESignature.NT_HEADER:
                raise ValueError(f"Invalid PE Signature. Expected 'PE\\0\\0', got {hex(pe_sig)}.")

            print(f"[+] Valid PE Signature found at {hex(pe_offset)}.")