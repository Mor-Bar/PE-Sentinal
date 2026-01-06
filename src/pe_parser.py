import os
import struct
import json
from src.constants import PESignature, PEOffsets, MachineType, OptionalHeaderMagic, SectionFlags

class PEParser:
    """
    A professional-grade PE (Portable Executable) parser.
    
    This class is responsible for static analysis of Windows executables (EXE/DLL).
    It supports two modes of operation:
    1. CLI Mode: Prints human-readable analysis to the console.
    2. JSON Mode: Aggregates data silently for automated processing.
    """

    def __init__(self, file_path: str, quiet: bool = False):
        """
        Initializes the PEParser.

        Args:
            file_path (str): The absolute or relative path to the PE file.
            quiet (bool): If True, suppresses standard console output (used for JSON mode).
        
        Raises:
            FileNotFoundError: If the provided file path does not exist.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"The file '{file_path}' was not found.")
        
        self.file_path = file_path
        self.quiet = quiet
        
        # ------------------------------------------------------------------
        # Data Container for JSON Output
        # This dictionary will accumulate all findings during the parsing process.
        # ------------------------------------------------------------------
        self.pe_data = {
            "file_metadata": {},
            "headers": {},
            "sections": [],
            "imports": [],
            "exports": []
        }

        # ------------------------------------------------------------------
        # Internal State Variables
        # Used to store offsets and sizes needed across different parsing stages.
        # ------------------------------------------------------------------
        self.pe_header_offset = 0
        self.num_sections = 0
        self.size_of_optional_header = 0
        self.optional_header_start = 0
        self.magic = 0
        self.sections = [] # Stores section info for RVA->Offset calculations

    def _log(self, message: str):
        """
        Helper method to print messages only if not in quiet mode.
        """
        if not self.quiet:
            print(message)

    def parse(self):
        """
        The main driver method that orchestrates the entire parsing workflow.
        
        It calls specific parsing methods in the correct order mandated by the PE format:
        DOS Header -> PE Signature -> File Header -> Optional Header -> Sections -> Data Directories.
        """
        from src.utils import calculate_sha256
        
        self._log(f"[*] Analyzing file: {self.file_path}")
        
        # ******************************************************************
        # STEP 1: File Identification & Hashing
        # ******************************************************************
        file_hash = calculate_sha256(self.file_path)
        self.pe_data["file_metadata"]["sha256"] = file_hash
        self.pe_data["file_metadata"]["path"] = self.file_path
        
        self._log(f"[*] SHA-256 Hash: {file_hash}")
        self._log("-" * 60)
        
        # Open the file once and pass the handle to sub-methods
        with open(self.file_path, "rb") as f:
            self._parse_dos_header(f)
            self._parse_pe_signature(f)
            self._parse_file_header(f)
            self._parse_optional_header(f)
            self._parse_section_headers(f)
            
            # These directories rely on data parsed in previous steps
            self._parse_export_directory(f)
            self._parse_import_directory(f)
            
        self._log("[SUCCESS] Parsing completed successfully.")

    def _parse_dos_header(self, f):
        """
        Parses the legacy DOS Header (first 64 bytes).
        Validates the 'MZ' magic number and finds the offset to the PE Header.
        """
        f.seek(0)
        dos_sig_data = f.read(2)
        
        if len(dos_sig_data) < 2:
            raise ValueError("File is too small to be a PE file.")

        dos_sig = struct.unpack("<H", dos_sig_data)[0]
        if dos_sig != PESignature.DOZ_HEADER:
            raise ValueError(f"Invalid DOS Header. Expected MZ (0x5A4D), got {hex(dos_sig)}.")

        self._log(f"[+] Valid DOS Header (MZ) found at offset 0x0.")

        # The field 'e_lfanew' is located at offset 0x3C (60) in the DOS Header.
        # It contains the 4-byte offset to the PE Signature.
        f.seek(PEOffsets.E_LFANEW)
        e_lfanew_data = f.read(4)
        self.pe_header_offset = struct.unpack("<I", e_lfanew_data)[0]
        
        # Save to JSON data
        self.pe_data["headers"]["dos_header"] = {"e_lfanew": hex(self.pe_header_offset)}
        self._log(f"[+] e_lfanew pointer found. PE Header is at offset: {hex(self.pe_header_offset)}")

    def _parse_pe_signature(self, f):
        """
        Validates the PE Signature ('PE\0\0') at the location pointed to by e_lfanew.
        """
        f.seek(self.pe_header_offset)
        pe_sig_data = f.read(4)
        pe_sig = struct.unpack("<I", pe_sig_data)[0]

        if pe_sig != PESignature.NT_HEADER:
            raise ValueError(f"Invalid PE Signature. Expected 'PE\\0\\0', got {hex(pe_sig)}.")

        self._log(f"[+] Valid PE Signature found at {hex(self.pe_header_offset)}.")

    def _parse_file_header(self, f):
        """
        Parses the COFF File Header (20 bytes).
        Extracts architecture (Machine), number of sections, and timestamp.
        """
        # The File Header starts immediately after the 4-byte PE Signature
        header_data = f.read(20)
        
        # Unpack format '<HHIIIHH':
        # Machine(H), NumberOfSections(H), TimeDateStamp(I), PointerToSymbolTable(I),
        # NumberOfSymbols(I), SizeOfOptionalHeader(H), Characteristics(H)
        unpacked_header = struct.unpack("<HHIIIHH", header_data)
        
        machine = unpacked_header[0]
        self.num_sections = unpacked_header[1]
        timestamp = unpacked_header[2]
        self.size_of_optional_header = unpacked_header[5] # Crucial for finding Section Table

        # Identify Architecture
        arch = "Unknown"
        if machine == MachineType.IMAGE_FILE_MACHINE_AMD64:
            arch = "x64 (64-bit)"
        elif machine == MachineType.IMAGE_FILE_MACHINE_I386:
            arch = "x86 (32-bit)"
        
        # Save to JSON
        self.pe_data["headers"]["file_header"] = {
            "machine": hex(machine),
            "architecture": arch,
            "num_sections": self.num_sections,
            "timestamp": timestamp
        }

        self._log("="*40)
        self._log("FILE HEADER INFO:")
        self._log(f"[-] Machine: {hex(machine)} ({arch})")
        self._log(f"[-] Number of Sections: {self.num_sections}")
        self._log(f"[-] Timestamp: {timestamp}")
        self._log(f"[-] Optional Header Size: {self.size_of_optional_header}")
        self._log("="*40)

    def _parse_optional_header(self, f):
        """
        Parses the Optional Header to determine PE format (32/64 bit), Entry Point, and Image Base.
        """
        self.optional_header_start = f.tell()
        
        # Read the first 2 bytes (Magic) to determine format
        magic_data = f.read(2)
        self.magic = struct.unpack("<H", magic_data)[0]

        entry_point = 0
        image_base = 0
        magic_name = "Unknown"

        # ******************************************************************
        # Handle Format Differences (PE32 vs PE32+)
        # ******************************************************************
        if self.magic == OptionalHeaderMagic.PE32_PLUS:
            magic_name = "PE32+ (64-bit)"
            # Skip: MajorLinker(1) + MinorLinker(1) + SizeOfCode(4) + InitData(4) + UnInitData(4) = 14 bytes
            f.seek(14, 1) 
            # Read: AddressOfEntryPoint(4), BaseOfCode(4), ImageBase(8)
            opt_data = f.read(16)
            unpacked_opt = struct.unpack("<IIQ", opt_data)
            entry_point = unpacked_opt[0]
            image_base = unpacked_opt[2]

        elif self.magic == OptionalHeaderMagic.PE32:
            magic_name = "PE32 (32-bit)"
            # Skip same 14 bytes
            f.seek(14, 1)
            # Read: AddressOfEntryPoint(4), BaseOfCode(4), BaseOfData(4), ImageBase(4)
            opt_data = f.read(16)
            unpacked_opt = struct.unpack("<IIII", opt_data)
            entry_point = unpacked_opt[0]
            image_base = unpacked_opt[3]
        
        # Save to JSON
        self.pe_data["headers"]["optional_header"] = {
            "magic": hex(self.magic),
            "format": magic_name,
            "entry_point": hex(entry_point),
            "image_base": hex(image_base)
        }

        self._log("OPTIONAL HEADER INFO:")
        self._log(f"[-] Magic: {hex(self.magic)} ({magic_name})")
        self._log(f"[-] Entry Point: {hex(entry_point)}")
        self._log(f"[-] Image Base: {hex(image_base)}")
        self._log("="*40)

    def _parse_section_headers(self, f):
        """
        Parses the Section Table.
        Extracts section names, addresses, permissions, and calculates Shannon Entropy.
        """
        from src.utils import convert_section_characteristics, rva_to_offset
        from src.entropy import calculate_entropy

        # Calculate Start of Section Table:
        # It begins immediately after the Optional Header ends.
        section_table_start = self.optional_header_start + self.size_of_optional_header
        f.seek(section_table_start)

        self._log("SECTION HEADERS:")
        self._log(f"{'Name':<10} {'VirtSize':<10} {'VirtAddr':<10} {'RawSize':<10} {'RawAddr':<10} {'Perms':<10} {'Entropy':<10}")
        self._log("-" * 80) 

        for _ in range(self.num_sections):
            # Each section header is exactly 40 bytes
            section_data = f.read(40)
            if len(section_data) < 40: break
            
            section_info = struct.unpack("<8sIIIIIIHHI", section_data)
            name = section_info[0].decode('utf-8', errors='ignore').strip('\x00')
            virtual_size = section_info[1]
            virtual_addr = section_info[2]
            raw_size = section_info[3]
            raw_addr = section_info[4]
            characteristics = section_info[9]

            # Cache section info for later RVA->Offset calculations
            self.sections.append({
                'Name': name,
                'VirtualAddr': virtual_addr,
                'VirtualSize': virtual_size,
                'RawAddr': raw_addr
            })

            perms = convert_section_characteristics(characteristics)

            # ******************************************************************
            # Entropy Calculation (Anomaly Detection)
            # ******************************************************************
            entropy_val = 0.0
            if raw_size > 0 and raw_addr > 0:
                current_pos = f.tell()      # Save loop position
                f.seek(raw_addr)            # Jump to actual section content
                data = f.read(raw_size)     # Read content
                entropy_val = calculate_entropy(data)
                f.seek(current_pos)         # Return to loop
            
            entropy_str = f"{entropy_val:.2f}"

            # Save to JSON
            self.pe_data["sections"].append({
                "name": name,
                "virtual_size": hex(virtual_size),
                "virtual_address": hex(virtual_addr),
                "raw_size": hex(raw_size),
                "raw_address": hex(raw_addr),
                "permissions": perms,
                "entropy": entropy_val
            })

            self._log(f"{name:<10} {hex(virtual_size):<10} {hex(virtual_addr):<10} {hex(raw_size):<10} {hex(raw_addr):<10} {perms:<10} {entropy_str:<10}")
        
        self._log("="*40)

    def _parse_export_directory(self, f):
        """
        Parses the Export Directory (if it exists).
        Typical for DLLs providing functions to other executables.
        """
        from src.utils import rva_to_offset
        
        # ******************************************************************
        # STEP 1: Determine Offset to Data Directories
        # ******************************************************************
        # The offset of the Data Directory array depends on whether it's PE32 or PE32+
        if self.magic == OptionalHeaderMagic.PE32_PLUS:
            data_dir_offset = 112
        elif self.magic == OptionalHeaderMagic.PE32:
            data_dir_offset = 96
        else:
            return

        # Export Directory is Index 0 in Data Directories
        export_entry_pos = self.optional_header_start + data_dir_offset
        f.seek(export_entry_pos)

        entry_data = f.read(8)
        export_rva, export_size = struct.unpack("<II", entry_data)

        if export_rva == 0: return # No exports found

        self._log("="*40)
        self._log("EXPORT DIRECTORY info:")
        self._log(f"[-] Export Table RVA: {hex(export_rva)}")
        
        # Convert RVA to File Offset to read from disk
        export_offset = rva_to_offset(export_rva, self.sections)
        self._log(f"[-] File Offset: {hex(export_offset)}")
        self._log("-" * 60)
        self._log("EXPORTED FUNCTIONS:")

        if export_offset > 0:
            f.seek(export_offset)
            export_data = f.read(40)
            if len(export_data) < 40: return
            
            # Unpack IMAGE_EXPORT_DIRECTORY
            parts = struct.unpack("<IIHHIIIIIII", export_data)
            name_rva = parts[4]
            num_names = parts[7]
            names_addr_rva = parts[9]
            ordinals_addr_rva = parts[10]

            # Get the DLL Name
            dll_name = "Unknown"
            name_offset = rva_to_offset(name_rva, self.sections)
            if name_offset > 0:
                f.seek(name_offset)
                dll_name_bytes = b""
                while True:
                    char = f.read(1)
                    if char == b'\x00': break
                    dll_name_bytes += char
                dll_name = dll_name_bytes.decode('utf-8', errors='ignore')
                self._log(f"[+] Module Name: {dll_name}")

            exported_funcs = []
            
            # ******************************************************************
            # STEP 2: Iterate Through Exported Functions
            # ******************************************************************
            if num_names > 0:
                names_offset = rva_to_offset(names_addr_rva, self.sections)
                ords_offset = rva_to_offset(ordinals_addr_rva, self.sections)
                
                self._log(f"[+] Found {num_names} named exports. Listing first 20:")
                
                for i in range(min(num_names, 20)): # Safety limit for console
                    # Read Name Pointer
                    f.seek(names_offset + (i * 4))
                    name_ptr_rva = struct.unpack("<I", f.read(4))[0]
                    
                    # Read Ordinal
                    f.seek(ords_offset + (i * 2))
                    ordinal = struct.unpack("<H", f.read(2))[0]
                    
                    # Read Function Name String
                    ptr_offset = rva_to_offset(name_ptr_rva, self.sections)
                    if ptr_offset > 0:
                        f.seek(ptr_offset)
                        func_name_b = b""
                        while True:
                            char = f.read(1)
                            if char == b'\x00': break
                            func_name_b += char
                        
                        func_name = func_name_b.decode('utf-8', errors='ignore')
                        self._log(f"    - {func_name} (Ordinal: {ordinal})")
                        exported_funcs.append({"name": func_name, "ordinal": ordinal})
            
            # Save to JSON
            self.pe_data["exports"] = {
                "dll_name": dll_name,
                "count": num_names,
                "functions": exported_funcs 
            }
        self._log("="*40)

    def _parse_import_directory(self, f):
        """
        Parses the Import Directory (Import Address Table - IAT).
        Extracts imported DLLs and their used functions.
        """
        from src.utils import rva_to_offset
        
        # ******************************************************************
        # STEP 1: Determine Architecture Specifics
        # ******************************************************************
        if self.magic == OptionalHeaderMagic.PE32_PLUS:
            data_dir_offset = 112
            thunk_size = 8      # 64-bit address
            thunk_format = "<Q"
        elif self.magic == OptionalHeaderMagic.PE32:
            data_dir_offset = 96
            thunk_size = 4      # 32-bit address
            thunk_format = "<I"
        else:
            return

        # Import Directory is Index 1 in Data Directories
        import_entry_pos = self.optional_header_start + data_dir_offset + 8 
        f.seek(import_entry_pos)

        entry_data = f.read(8)
        import_rva, import_size = struct.unpack("<II", entry_data)

        if import_rva == 0: return

        self._log("="*40)
        self._log("IMPORT DIRECTORY info:")
        self._log(f"[-] Import Table RVA: {hex(import_rva)}")
        
        table_offset = rva_to_offset(import_rva, self.sections)
        self._log(f"[-] File Offset: {hex(table_offset)}")
        self._log("-" * 60)
        self._log("IMPORTED FUNCTIONS:")
        
        f.seek(table_offset)
        
        # ******************************************************************
        # STEP 2: Loop Through Import Descriptors (DLLs)
        # ******************************************************************
        while True:
            descriptor_data = f.read(20)
            # A null descriptor indicates the end of the table
            if len(descriptor_data) < 20 or descriptor_data == b'\x00'*20:
                break 
            
            # Struct: OriginalFirstThunk(0), Time(1), Forwarder(2), NameRVA(3), FirstThunk(4)
            descriptor = struct.unpack("<IIIII", descriptor_data)
            original_first_thunk = descriptor[0] # Points to function names
            name_rva = descriptor[3]             # Points to DLL name
            
            current_pos = f.tell() # Save position in descriptor array
            
            # --- Get DLL Name ---
            name_offset = rva_to_offset(name_rva, self.sections)
            dll_name = "Unknown"
            if name_offset > 0:
                f.seek(name_offset)
                dll_name_bytes = b""
                while True:
                    char = f.read(1)
                    if char == b'\x00': break
                    dll_name_bytes += char
                dll_name = dll_name_bytes.decode('utf-8', errors='ignore')

            self._log(f"\n[+] {dll_name}")
            
            imported_funcs = []

            # ******************************************************************
            # STEP 3: Loop Through Thunks (Functions)
            # ******************************************************************
            if original_first_thunk > 0:
                thunk_offset = rva_to_offset(original_first_thunk, self.sections)
                if thunk_offset > 0:
                    f.seek(thunk_offset)
                    
                    while True:
                        thunk_data = f.read(thunk_size)
                        if len(thunk_data) < thunk_size: break
                        
                        thunk_val = struct.unpack(thunk_format, thunk_data)[0]
                        if thunk_val == 0: break # End of thunk table
                        
                        # Check for Ordinal Import (High bit set)
                        is_ordinal = False
                        if thunk_size == 8: is_ordinal = (thunk_val & 0x8000000000000000) != 0
                        else: is_ordinal = (thunk_val & 0x80000000) != 0

                        if is_ordinal:
                            ord_val = thunk_val & 0xFFFF
                            self._log(f"    - [Ordinal: {ord_val}]")
                            imported_funcs.append({"ordinal": ord_val})
                        else:
                            # Import by Name
                            name_rva_ptr = thunk_val & 0x7FFFFFFF 
                            name_ptr_offset = rva_to_offset(name_rva_ptr, self.sections)
                            
                            if name_ptr_offset > 0:
                                temp_pos = f.tell() 
                                f.seek(name_ptr_offset)
                                f.read(2) # Skip Hint (2 bytes)
                                
                                func_bytes = b""
                                while True:
                                    char = f.read(1)
                                    if char == b'\x00': break
                                    func_bytes += char
                                f_name = func_bytes.decode('utf-8', errors='ignore')
                                
                                self._log(f"    - {f_name}")
                                imported_funcs.append({"name": f_name})
                                f.seek(temp_pos)

            # Save to JSON
            self.pe_data["imports"].append({
                "dll": dll_name,
                "functions": imported_funcs
            })

            # Return to descriptor loop
            f.seek(current_pos)
            
        self._log("="*40)