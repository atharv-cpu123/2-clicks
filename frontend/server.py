"""Compatibility entry point for starting the FastAPI-backed frontend."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

try:
    import uvicorn
    from backend.app.main import app
except ImportError as error:
    raise SystemExit(
        "FastAPI dependencies are missing. Install them with: "
        "py -m pip install -r requirements.txt"
    ) from error

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
