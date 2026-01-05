import sys
import os
from src.pe_parser import PEParser

def main():
    # Let's try to parse the system's Notepad
    # We use os.path.join for cross-platform compatibility
    target_file = os.path.join("C:\\", "Windows", "System32", "notepad.exe")
    
    print(f"[*] Analyzing file: {target_file}")

    try:
        parser = PEParser(target_file)
        parser.parse()
        print("[SUCCESS] Parsing completed successfully.")
        
    except Exception as e:
        print(f"[ERROR] An error occurred: {e}")

if __name__ == "__main__":
    main()