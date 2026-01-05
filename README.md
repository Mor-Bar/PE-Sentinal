# PE-Sentinel

PE-Sentinel is a static analysis tool designed to parse and inspect the internal structure of Windows Portable Executable (PE) files. Written in modular, type-safe Python, it allows security researchers and developers to extract critical metadata from executables (EXE) and dynamic link libraries (DLL) without executing them.

This tool was built with a focus on clean architecture, readability, and adherence to modern software engineering best practices.

## Table of Contents

- [Overview](#overview)
- [Technical Concepts & Architecture](#technical-concepts--architecture)
- [Features](#features)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Example Output](#example-output)

## Overview

Static analysis is the process of examining a file's code and structure without running it. This is a fundamental step in malware analysis and reverse engineering. PE-Sentinel automates the extraction of headers defined by the Microsoft PE and COFF specifications, providing a human-readable summary of the binary's organization.

## Technical Concepts & Architecture

For those new to reverse engineering, understanding the PE format is essential. A Windows executable is not just a blob of code; it is a highly structured file acting as a roadmap for the operating system loader. PE-Sentinel parses the following components sequentially:

### 1. DOS Header & Stub
Every PE file starts with a legacy DOS Header. It begins with the magic number `MZ` (Mark Zbikowski).
* **Purpose:** Ensures compatibility. If a PE file is run on DOS, it prints "This program cannot be run in DOS mode."
* **Tool Action:** Validates the `MZ` signature and reads the `e_lfanew` field at offset 0x3C, which is a pointer to the actual PE header.

### 2. PE Signature & File Header (COFF)
Located at the offset pointed to by `e_lfanew`.
* **Purpose:** Contains vital metadata such as the target machine architecture (x86 vs x64), the timestamp of compilation, and the number of sections.
* **Tool Action:** Identifies the architecture and determines how many sections need to be parsed later.

### 3. Optional Header
Despite the name, this header is mandatory for executable files.
* **Purpose:** Defines how the file should be loaded into memory. It includes the `AddressOfEntryPoint` (where execution begins) and the `ImageBase` (preferred memory address).
* **Tool Action:** Parses the "Magic" field to distinguish between PE32 (32-bit) and PE32+ (64-bit) formats, as the structure sizes differ between them.

### 4. Section Headers
The actual content of the program is divided into sections (e.g., `.text` for code, `.data` for variables).
* **Purpose:** Each section has a header defining its size, location, and memory permissions (Read, Write, Execute).
* **Tool Action:** Iterates through the section table, extracts virtual and raw addresses, and decodes the characteristics flags into human-readable permissions (e.g., `R-X` for executable code).

## Features

* **Header Validation:** Verifies file integrity via DOS and PE signatures.
* **Architecture Detection:** Automatically distinguishes between x86 and x64 binaries.
* **Deep Inspection:** Extracts Entry Point, Image Base, and compilation timestamps.
* **Permission Decoding:** Translates bitwise section flags into readable strings (`RWX`).
* **CLI Support:** Fully functional Command Line Interface with argument parsing and error handling.
* **Type Safety:** Implemented using strict Python type hinting for reliability.

## Project Structure

The project follows a `src-layout` to ensure modularity and separation of concerns.

```text
PE-SENTINEL/
├── main.py             # Entry point for the CLI tool
├── src/
│   ├── __init__.py     # Package initialization
│   ├── constants.py    # PE format magic numbers and offsets
│   ├── pe_parser.py    # Core parsing logic and class definitions
│   └── utils.py        # Helper functions (e.g., flag decoding)
├── .gitignore
├── LICENSE
└── README.md

## Installation

Ensure you have Python 3.8 or higher installed.

1.  Clone the repository:
    ```bash
    git clone [https://github.com/YOUR_USERNAME/PE-Sentinel.git](https://github.com/YOUR_USERNAME/PE-Sentinel.git)
    cd PE-Sentinel
    ```

2.  No external dependencies are required. The tool uses only Python's standard library.

## Usage

Run the tool via the command line by providing the path to a target PE file.

**Basic Usage:**
```bash
python main.py C:\Windows\System32\notepad.exe
```

**View Help Menu:**
```bash
python main.py -h
```

**Example Output**
```bash
[*] Analyzing file: C:\Windows\System32\notepad.exe
[+] Valid DOS Header (MZ) found at offset 0x0.
[+] e_lfanew pointer found. PE Header is at offset: 0xf8
[+] Valid PE Signature found at 0xf8.
========================================
FILE HEADER INFO:
[-] Machine: 0x8664 (x64 (64-bit))
[-] Number of Sections: 8
[-] Timestamp: 2088023820
[-] Optional Header Size: 240
========================================
OPTIONAL HEADER INFO:
[-] Magic: 0x20b (PE32+ (64-bit))
[-] Entry Point: 0x19b0
[-] Image Base: 0x140000000
========================================
SECTION HEADERS:
Name       VirtSize   VirtAddr   RawSize    RawAddr    Perms     
----------------------------------------------------------------------
.text      0x266e2    0x1000     0x27000    0x1000     R-X       
.rdata     0xa5d8     0x29000    0xb000     0x29000    R--       
.data      0x2740     0x34000    0x1000     0x34000    RW-       
.pdata     0x120c     0x37000    0x2000     0x35000    R--       
.rsrc      0x1e1d0    0x3a000    0x1f000    0x38000    R--       
.reloc     0x350      0x59000    0x1000     0x57000    R--       
========================================
[SUCCESS] Parsing completed successfully.
```