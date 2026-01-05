import os
import struct
from src.constants import PESignature, PEOffsets, MachineType, OptionalHeaderMagic, SectionFlags

class PEParser:
    """
    A class to parse Windows Portable Executable (PE) files.
    Modular design with separate methods for each header.
    """

    def __init__(self, file_path: str):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"The file '{file_path}' was not found.")
        self.file_path = file_path
        
        # State variables
        self.pe_header_offset = 0
        self.num_sections = 0
        self.size_of_optional_header = 0
        self.optional_header_start = 0

    def parse(self):
        """
        Main driver method that orchestrates the parsing process.
        """
        print(f"[*] Analyzing file: {self.file_path}")
        
        with open(self.file_path, "rb") as f:
            self._parse_dos_header(f)
            self._parse_pe_signature(f)
            self._parse_file_header(f)
            self._parse_optional_header(f)
            self._parse_section_headers(f)
            
        print("[SUCCESS] Parsing completed successfully.")

    def _parse_dos_header(self, f):
        """Validates the DOS Header and finds e_lfanew."""
        f.seek(0)
        dos_sig_data = f.read(2)
        
        if len(dos_sig_data) < 2:
            raise ValueError("File is too small.")

        dos_sig = struct.unpack("<H", dos_sig_data)[0]
        if dos_sig != PESignature.DOZ_HEADER:
            raise ValueError(f"Invalid DOS Header. Expected MZ, got {hex(dos_sig)}.")

        print(f"[+] Valid DOS Header (MZ) found at offset 0x0.")

        # Get offset to PE Header
        f.seek(PEOffsets.E_LFANEW)
        e_lfanew_data = f.read(4)
        self.pe_header_offset = struct.unpack("<I", e_lfanew_data)[0]
        print(f"[+] e_lfanew pointer found. PE Header is at offset: {hex(self.pe_header_offset)}")

    def _parse_pe_signature(self, f):
        """Validates the PE Signature."""
        f.seek(self.pe_header_offset)
        pe_sig_data = f.read(4)
        pe_sig = struct.unpack("<I", pe_sig_data)[0]

        if pe_sig != PESignature.NT_HEADER:
            raise ValueError(f"Invalid PE Signature. Expected 'PE\\0\\0', got {hex(pe_sig)}.")

        print(f"[+] Valid PE Signature found at {hex(self.pe_header_offset)}.")

    def _parse_file_header(self, f):
        """Parses the COFF File Header to get machine type and section count."""
        # File Header starts right after PE Signature (4 bytes)
        # We don't need to seek because we just read the signature
        header_data = f.read(20)
        unpacked_header = struct.unpack("<HHIIIHH", header_data)
        
        machine = unpacked_header[0]
        self.num_sections = unpacked_header[1]
        timestamp = unpacked_header[2]
        self.size_of_optional_header = unpacked_header[5]

        # Identify Architecture
        arch = "Unknown"
        if machine == MachineType.IMAGE_FILE_MACHINE_AMD64:
            arch = "x64 (64-bit)"
        elif machine == MachineType.IMAGE_FILE_MACHINE_I386:
            arch = "x86 (32-bit)"
        
        print("="*40)
        print("FILE HEADER INFO:")
        print(f"[-] Machine: {hex(machine)} ({arch})")
        print(f"[-] Number of Sections: {self.num_sections}")
        print(f"[-] Timestamp: {timestamp}")
        print(f"[-] Optional Header Size: {self.size_of_optional_header}")
        print("="*40)

    def _parse_optional_header(self, f):
        """Parses the Optional Header for Entry Point and Image Base."""
        self.optional_header_start = f.tell()
        
        magic_data = f.read(2)
        magic = struct.unpack("<H", magic_data)[0]

        entry_point = 0
        image_base = 0
        magic_name = "Unknown"

        if magic == OptionalHeaderMagic.PE32_PLUS:
            magic_name = "PE32+ (64-bit)"
            f.seek(14, 1) # Skip to EntryPoint
            opt_data = f.read(16)
            unpacked_opt = struct.unpack("<IIQ", opt_data)
            entry_point = unpacked_opt[0]
            image_base = unpacked_opt[2]

        elif magic == OptionalHeaderMagic.PE32:
            magic_name = "PE32 (32-bit)"
            f.seek(14, 1)
            opt_data = f.read(16)
            unpacked_opt = struct.unpack("<IIII", opt_data)
            entry_point = unpacked_opt[0]
            image_base = unpacked_opt[3]

        else:
            raise ValueError(f"Unknown Optional Header Magic: {hex(magic)}")

        print("OPTIONAL HEADER INFO:")
        print(f"[-] Magic: {hex(magic)} ({magic_name})")
        print(f"[-] Entry Point: {hex(entry_point)}")
        print(f"[-] Image Base: {hex(image_base)}")
        print("="*40)

    def _parse_section_headers(self, f):
        """Parses and prints the Section Headers table with permissions."""
        from src.utils import convert_section_characteristics # Import helper locally

        # Calculate exactly where the Section Table starts
        section_table_start = self.optional_header_start + self.size_of_optional_header
        f.seek(section_table_start)

        print("SECTION HEADERS:")
        # Added 'Perms' column header
        print(f"{'Name':<10} {'VirtSize':<10} {'VirtAddr':<10} {'RawSize':<10} {'RawAddr':<10} {'Perms':<10}")
        print("-" * 70) # Extended line length

        for _ in range(self.num_sections):
            section_data = f.read(40)
            if len(section_data) < 40:
                break
            
            # Struct: Name(8s), VirtSize(I), VirtAddr(I), RawSize(I), RawAddr(I), 
            #         RelocPtr(I), LineNumPtr(I), NumReloc(H), NumLineNum(H), Characteristics(I)
            # format: <8sIIIIIIHHI
            section_info = struct.unpack("<8sIIIIIIHHI", section_data)
            
            name = section_info[0].decode('utf-8', errors='ignore').strip('\x00')
            virtual_size = section_info[1]
            virtual_addr = section_info[2]
            raw_size = section_info[3]
            raw_addr = section_info[4]
            characteristics = section_info[9] # This is the last field

            # Use our utility function to convert int to string (e.g. 0x60000020 -> 'R-X')
            perms = convert_section_characteristics(characteristics)

            print(f"{name:<10} {hex(virtual_size):<10} {hex(virtual_addr):<10} {hex(raw_size):<10} {hex(raw_addr):<10} {perms:<10}")
        
        print("="*40)