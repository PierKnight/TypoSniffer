from pathlib import Path
import re

import click
from typeguard import typechecked

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