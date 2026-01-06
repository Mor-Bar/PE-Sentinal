# PE-Sentinel: Advanced Static Analysis Engine

**Version:** 1.0.0  
**Author:** Mor Bar  
**License:** MIT  
**Status:** Production Ready

---

## Overview

**PE-Sentinel** is a professional-grade, dependency-free static analysis tool designed for the forensic inspection of Windows Portable Executable (PE) files. Written entirely in Python using the standard library, it provides a robust framework for dissecting executables (EXE) and libraries (DLL) without execution.

In the domain of cybersecurity and malware analysis, **Static Analysis** is the first line of defense. It allows analysts to map the capabilities, dependencies, and structure of a binary before determining if it is safe to run in a sandbox (Dynamic Analysis). PE-Sentinel automates this process, extracting critical indicators of compromise (IOCs) and structural anomalies.

## Key Capabilities

### 1. Forensic Header Analysis
Parses the MS-DOS, COFF File, and Optional Headers to extract metadata crucial for identifying the target environment:
* **Architecture Detection:** Differentiates between x86 (32-bit) and x64 (64-bit) binaries.
* **Timestamp Verification:** Extracts the compilation timestamp (TimeDateStamp), which can indicate if a file is masquerading as an older system file.
* **Entry Point Resolution:** Identifies the precise memory address where code execution begins.

### 2. Dependency & Capability Mapping (IAT/EAT)
* **Import Address Table (IAT):** Reconstructs the list of external DLLs and functions the binary consumes. This reveals the file's intent (e.g., a file importing `CryptEncrypt` and `InternetOpen` suggests ransomware behavior).
* **Export Directory:** Parses exported functions (by Name and Ordinal), useful for analyzing DLLs and helper modules.

### 3. Anomaly Detection via Shannon Entropy
Malware often uses packers or encryption to hide its malicious payload. PE-Sentinel calculates the **Shannon Entropy** for each section to detect these anomalies.
* **Low Entropy (0-6):** Standard code or text.
* **High Entropy (7-8):** Compressed, packed, or encrypted data (High probability of malware).

### 4. Dual-Mode Output
* **CLI Mode:** Formatted, human-readable tables for manual investigation by analysts.
* **JSON Mode:** Structured, machine-readable output designed for integration with SIEM systems (e.g., Splunk, ELK) or automated pipelines.

---

## Technical Deep Dive

This section explains the core concepts implemented in the PE-Sentinel engine.

### Relative Virtual Addresses (RVA) vs. Raw Offsets
One of the biggest challenges in parsing PE files is the discrepancy between memory and disk.
* **RVA (Relative Virtual Address):** The address of an item once loaded into memory (RAM).
* **Raw Offset:** The actual position of the byte on the hard drive.

PE-Sentinel implements a custom translation engine that iterates through the Section Headers to map RVAs to Raw Offsets mathematically:
> `RawOffset = RVA - VirtualAddress + PointerToRawData`

### Entropy Calculation Logic
To detect packed malware, the tool analyzes the byte distribution of each section using the Shannon Entropy formula:

> H(X) = - Σ p(x) * log2(p(x))

Where `p(x)` is the probability of byte `x` appearing in the data. The result is a float between 0.0 and 8.0.

**Example Scenario:**
* **Notepad.exe (.text section):** Entropy ~6.2 (Normal machine code).
* **Malicious.exe (.text section):** Entropy ~7.8 (The code is encrypted/packed to evade antivirus).

---

## Installation

PE-Sentinel is built with **zero external dependencies**. It requires only a standard Python 3.8+ environment.

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/Mor-Bar/PE-Sentinel.git](https://github.com/Mor-Bar/PE-Sentinel.git)
    cd PE-Sentinel
    ```

2.  **Verify installation:**
    ```bash
    python main.py -h
    ```

---

## Usage Guide

### Mode 1: Analyst View (CLI)
Use this mode when manually inspecting a file. It presents data in aligned tables with visual separators.

**Command:**
```bash
python main.py target_file.exe
```

## Sample Output:

```bash
[*] Analyzing file: C:\Windows\System32\notepad.exe
[*] SHA-256 Hash: 84b484fd...

SECTION HEADERS:
Name       VirtSize   VirtAddr   RawSize    RawAddr    Perms      Entropy   
--------------------------------------------------------------------------------
.text      0x266e2    0x1000     0x27000    0x1000     R-X        6.23      
.data      0x2740     0x34000    0x1000     0x34000    RW-        1.62      
.rsrc      0x1e1d0    0x3a000    0x1f000    0x38000    R--        6.97      

IMPORTED FUNCTIONS:
[+] KERNEL32.dll
    - CreateFileW
    - WriteFile
    - CloseHandle
```

## Mode 2: Automation View (JSON)
Use this mode to pipe results into other tools or save logs. All output is strictly strictly valid JSON.

**Command:**

```Bash
python main.py target_file.exe --json > report.json
```

**JSON Structure:**

```JSON
{
    "file_metadata": {
        "sha256": "84b484...",
        "path": "target_file.exe"
    },
    "sections": [
        {
            "name": ".text",
            "virtual_address": "0x1000",
            "entropy": 7.92,
            "permissions": "R-X"
        }
    ],
    "imports": [
        {
            "dll": "USER32.dll",
            "functions": [
                { "name": "GetKeystate" },
                { "ordinal": 124 }
            ]
        }
    ]
}
```

##  Project Structure
The project is structured to separate parsing logic from utility functions, ensuring maintainability and scalability.

```Pl

PE-Sentinel/
├── main.py                 # Entry Point. Handles argument parsing and output routing.
├── README.md               # Documentation.
└── src/
    ├── pe_parser.py        # Core Engine. Contains the PEParser class and flow logic.
    ├── entropy.py          # Math Module. Implementation of Shannon Entropy.
    ├── utils.py            # Helpers. RVA conversion, Permission mapping, Timestamp parsing.
    └── constants.py        # Definitions. Magic numbers, Signature constants, Machine Types.
```

## Security & Ethics
This tool is intended for educational purposes, security research, and defensive analysis. Users are responsible for ensuring they have permission to analyze the files they target. The author assumes no liability for misuse of this tool.

## 🤝 Contributing 🤝
Contributions are welcome. If you find a bug or want to add a feature (e.g., YARA integration, heuristic scanning), please submit a Pull Request.

1 - Fork the Project

2 - Create your Feature Branch (git checkout -b feature/AmazingFeature)

3 - Commit your Changes (git commit -m 'Add some AmazingFeature')

4 - Push to the Branch (git push origin feature/AmazingFeature)

5 - Open a Pull Request