"""Run scan, risk analysis, then automatic medium-risk sandbox remediation."""

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
STEPS = [
    ROOT / "agents/scanner/scanner.py",
    ROOT / "agents/risk-analyst/risk_analyst.py",
    ROOT / "agents/responder/auto_remediate.py",
]


def main():
    for step in STEPS:
        print(f"\n========== Running {step.relative_to(ROOT)} ==========")
        result = subprocess.run([sys.executable, str(step)], cwd=ROOT, check=False)
        if result.returncode:
            print(f"[STOPPED] {step.name} exited with code {result.returncode}")
            return result.returncode
    print("\n[COMPLETE] Scan, risk analysis, and automatic sandbox remediation finished.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
