
import os
from pathlib import Path


cfg = []

FOLDER = Path(os.path.expanduser("~/.typosniffer"))

def load():
    global cfg
    os.makedirs(FOLDER, exist_ok=True)
    cfg = ["test"]