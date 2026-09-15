"""
Top-level detect.py wrapper — run from project root:
    python detect.py --input file.exe --ffnn-model ./baselines --ensemble
"""
import sys
import os

# Insert src/ at position 0 BEFORE any other imports
_src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
sys.path.insert(0, _src)

# Now run the real detect main
from detect_impl import main
if __name__ == "__main__":
    main()