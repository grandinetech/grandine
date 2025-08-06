"""
Entry point for utils module CLI tools.
"""

import sys
from pathlib import Path

# Add current directory to path for relative imports
sys.path.insert(0, str(Path(__file__).parent))

if __name__ == "__main__":
    # Check if we're being called as utils.static_analyzer
    if len(sys.argv) > 0 and "static_analyzer" in sys.argv[0]:
        from static_analyzer import main
        sys.exit(main())
    else:
        print("Usage: python -m utils.static_analyzer <repo_path> --out <json_path>")
        sys.exit(1)