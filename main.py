import sys
import argparse
from src.pe_parser import PEParser

def main():
    # 1. Initialize the Argument Parser
    parser = argparse.ArgumentParser(
        description="PE-Sentinel: A professional static analysis tool for Windows PE files.",
        epilog="Example: python main.py C:\\Windows\\System32\\notepad.exe"
    )

    # 2. Define the arguments
    parser.add_argument(
        "file_path",
        help="The absolute or relative path to the target PE file (exe/dll)."
    )

    # 3. Parse the arguments from command line
    args = parser.parse_args()

    # 4. Run the tool logic
    try:
        # We access the argument using the name we gave it above (args.file_path)
        pe_tool = PEParser(args.file_path)
        pe_tool.parse()
        
    except FileNotFoundError as e:
        print(f"[ERROR] File Check Failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[CRITICAL ERROR] An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()