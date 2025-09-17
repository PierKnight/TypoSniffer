import os
import subprocess
import sys
import click
from typosniffer.config.config import CONFIG


@click.group()
def config():
    """Manage config"""


@config.command()
def open():
    """Open config file with system editor"""


    if sys.platform.startswith("win"):
        os.startfile(CONFIG)
    elif sys.platform.startswith("darwin"):  # macOS
        subprocess.run(["open", CONFIG])
    else:  # Linux and others
        subprocess.run(["xdg-open", CONFIG])
