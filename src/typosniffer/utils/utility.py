from concurrent.futures import ProcessPoolExecutor, as_completed
from importlib import resources
from pathlib import Path
import re
from typing import List, Optional
import click
from typeguard import typechecked

from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from typosniffer.utils.console import console

@typechecked
def validate_regex(pattern: re.Pattern, message: str = None):
    """Return a callback function that validates the argument against the given pattern."""
    def callback(ctx, param, value):
        if not re.match(pattern, value):
            raise click.BadParameter(message if message else f"'{value}' does not match pattern '{pattern}'" )
        return value
    return callback


@typechecked
def read_lines(file: Path) -> list[str]:
    
    tld_dictionary = []
    with open(file, "r", encoding="utf-8") as f:
        for line in f:
            if not line.startswith("#"):
                tld_dictionary.append(line.strip().lower())
    return tld_dictionary

@typechecked
def get_dictionary(file: str) -> Path:
    return resources.files("typosniffer").joinpath("dictionary").joinpath(file)

@typechecked
def punicode_to_unicode(s: str) -> str:
    return s.encode("ascii").decode("idna")

def list_file_option(ctx, param, value: str) -> Optional[List[str]]:
    if value is None:
        return None
    return read_lines(Path(value))


def comma_separated_option(ctx, param, value: str) -> List[str]:
    if value is None:
        return None
    return value.split(",")

"""
def launch_thread_task(datas: list[any], task, parameters, max_workers: int, on_result):
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("[green]{task.completed}/{task.total} domain file scanned"),
            console=console
        ) as progress:
            
            future_to_task = {executor.submit(task, parameters(data)) for data in datas}
            
            for future in as_completed(future_to_task):
                try:
                    
                except Exception as e
"""