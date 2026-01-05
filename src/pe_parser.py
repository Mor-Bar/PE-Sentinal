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
        Validates DOS Header, parses NT Headers and File Header.
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
            f.seek(PEOffsets.E_LFANEW)
            e_lfanew_data = f.read(4)
            pe_offset = struct.unpack("<I", e_lfanew_data)[0]
            
            print(f"[+] e_lfanew pointer found. PE Header is at offset: {hex(pe_offset)}")

            # --- 3. Validate PE Signature ---
            f.seek(pe_offset)
            pe_sig_data = f.read(4)
            pe_sig = struct.unpack("<I", pe_sig_data)[0]

            if pe_sig != PESignature.NT_HEADER:
                raise ValueError(f"Invalid PE Signature. Expected 'PE\\0\\0', got {hex(pe_sig)}.")

            print(f"[+] Valid PE Signature found at {hex(pe_offset)}.")

            # --- 4. Parse COFF File Header ---
            # The File Header starts immediately after the PE Signature.
            # It is exactly 20 bytes long.
            header_data = f.read(20)
            
            # Unpack format: '<HHIIIHH' (20 bytes total)
            # H = unsigned short (2 bytes), I = unsigned int (4 bytes)
            # We only care about the first 2 fields for now: Machine and NumberOfSections.
            # The rest are TimeDateStamp, SymbolTable pointers, etc.
            unpacked_header = struct.unpack("<HHIIIHH", header_data)
            
            machine = unpacked_header[0]
            num_sections = unpacked_header[1]
            timestamp = unpacked_header[2] # TimeDateStamp is the 3rd field

            # Identify Architecture
            arch = "Unknown"
            from src.constants import MachineType # Import locally to use enum names
            
            if machine == MachineType.IMAGE_FILE_MACHINE_AMD64:
                arch = "x64 (64-bit)"
            elif machine == MachineType.IMAGE_FILE_MACHINE_I386:
                arch = "x86 (32-bit)"
            
            print("="*40)
            print("FILE HEADER INFO:")
            print(f"[-] Machine: {hex(machine)} ({arch})")
            print(f"[-] Number of Sections: {num_sections}")
            print(f"[-] Timestamp: {timestamp}")
            print("="*40)

            # --- 5. Parse Optional Header ---
            # We are now pointing at the start of the Optional Header.
            # First, read the Magic number (2 bytes) to know format.
            magic_data = f.read(2)
            magic = struct.unpack("<H", magic_data)[0]

            from src.constants import OptionalHeaderMagic # Import local

            # Define format based on architecture
            if magic == OptionalHeaderMagic.PE32_PLUS:
                magic_name = "PE32+ (64-bit)"
                # Skip: MajorLinker(1) + MinorLinker(1) + SizeOfCode(4) + SizeOfInitData(4) + SizeOfUnInitData(4) = 14 bytes
                f.seek(14, 1) # '1' means relative seek from current position
                
                # Now at AddressOfEntryPoint. 
                # Struct: AddressOfEntryPoint(4), BaseOfCode(4), ImageBase(8)
                opt_data = f.read(16)
                unpacked_opt = struct.unpack("<IIQ", opt_data)
                
                entry_point = unpacked_opt[0]
                image_base = unpacked_opt[2] # Index 2 because 'Q' (8 bytes) is the 3rd element

            elif magic == OptionalHeaderMagic.PE32:
                magic_name = "PE32 (32-bit)"
                # Skip same 14 bytes
                f.seek(14, 1)
                
                # Struct: AddressOfEntryPoint(4), BaseOfCode(4), BaseOfData(4), ImageBase(4)
                # Note: 32-bit has an extra field 'BaseOfData'
                opt_data = f.read(16)
                unpacked_opt = struct.unpack("<IIII", opt_data)
                
                entry_point = unpacked_opt[0]
                image_base = unpacked_opt[3] # Index 3 is ImageBase

            else:
                raise ValueError(f"Unknown Optional Header Magic: {hex(magic)}")

            print("="*40)
            print("OPTIONAL HEADER INFO:")
            print(f"[-] Magic: {hex(magic)} ({magic_name})")
            print(f"[-] Entry Point: {hex(entry_point)}")
            print(f"[-] Image Base: {hex(image_base)}")
            print("="*40)