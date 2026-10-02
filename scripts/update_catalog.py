from __future__ import annotations
import subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
for script in ("discover.py","validate.py"):
 print(f"=== {script} ==="); subprocess.run([sys.executable,str(ROOT/"scripts"/script)],check=True)
print("Catalog update complete.")
