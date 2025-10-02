import os
from pathlib import Path

from typeguard import install_import_hook


FOLDER = Path(os.path.expanduser("~/.typosniffer"))

install_import_hook('typosniffer')