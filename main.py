import sys
import argparse
import json
from src.pe_parser import PEParser

def main():
    parser = argparse.ArgumentParser(
        description="PE-Sentinel: A professional static analysis tool for Windows PE files.",
        epilog="Example: python main.py C:\\Windows\\System32\\notepad.exe --json"
    )

    parser.add_argument(
        "file_path",
        help="The absolute or relative path to the target PE file (exe/dll)."
    )

    # New Flag: JSON Output
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output the analysis results in JSON format (ideal for automation)."
    )

    args = parser.parse_args()

    try:
        # We pass the 'quiet' flag based on whether the user asked for JSON
        # If --json is True, we want the parser to be quiet (no text output)
        pe_tool = PEParser(args.file_path, quiet=args.json)
        pe_tool.parse()

        # If JSON was requested, we pull the data and print it cleanly
        if args.json:
            print(json.dumps(pe_tool.pe_data, indent=4))
        
    except FileNotFoundError as e:
        if args.json:
            print(json.dumps({"error": str(e)}))
        else:
            print(f"[ERROR] File Check Failed: {e}")
        sys.exit(1)
    except Exception as e:
        if args.json:
            print(json.dumps({"error": str(e)}))
        else:
            print(f"[CRITICAL ERROR] An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()