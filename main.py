import sys
import os
from src.pe_parser import PEParser

def main():
    # Target file to analyze
    target_file = os.path.join("C:\\", "Windows", "System32", "notepad.exe")
    
    # We don't need to print "Analyzing..." here anymore, 
    # because the PEParser class handles all output internally.
    try:
        parser = PEParser(target_file)
        parser.parse()
        
    except Exception as e:
        print(f"[ERROR] An error occurred: {e}")

if __name__ == "__main__":
    main()