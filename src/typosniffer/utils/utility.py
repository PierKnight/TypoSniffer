from importlib import resources
from pathlib import Path
import re
from typing import List
import click
from typeguard import typechecked
import tldextract

@typechecked
def validate_regex(pattern: re.Pattern, message: str = None):
    """Return a callback function that validates the argument against the given pattern."""
    def callback(ctx, param, value):

        values_to_check = [value] if isinstance(value, str) else value
        print(values_to_check)
        for val in values_to_check:
            if not re.match(pattern, val):
                raise click.BadParameter(message if message else f"'{val}' does not match pattern '{pattern}'" )
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

def list_file_option(ctx, param, value: str) -> List[str]:
    if value is None:
        return None
    
    return read_lines(Path(value))


def comma_separated_option(ctx, param, value: str) -> List[str]:
    if value is None:
        return None
    return value.split(",")


def strip_tld(domain: str) -> str:
    extracted = tldextract.extract(domain)
    return extracted.suffix, f"{extracted.subdomain}.{extracted.domain}" if extracted.subdomain else extracted.domain

