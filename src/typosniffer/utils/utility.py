import csv
from dataclasses import asdict, is_dataclass
from enum import Enum
from importlib import resources
import json
from pathlib import Path
import socket
from typing import Any, Callable, List, Generator
import click
from pydantic import BaseModel
from typeguard import typechecked
from typosniffer.utils import console
import tldextract

from typosniffer.utils.exceptions import InternetMissing

@typechecked
def read_lines(file: Path) -> list[str]:
    
    tld_dictionary = []
    with open(file, "r", encoding="utf-8") as f:
        for line in f:
            if not line.startswith("#"):
                tld_dictionary.append(line.strip().lower())
    return tld_dictionary

@typechecked
def get_resource(file: str) -> Path:
    return resources.files("typosniffer").joinpath("resources").joinpath(file)

@typechecked
def punicode_to_unicode(s: str) -> str:
    return s.encode("ascii").decode("idna")

def list_file_option(ctx, param, value: str) -> List[str]:
    if value is None:
        return None
    
    return read_lines(Path(value))


def strip_tld(domain: str) -> str:
    extracted = tldextract.extract(domain)
    return extracted.suffix, f"{extracted.subdomain}.{extracted.domain}" if extracted.subdomain else extracted.domain


def to_serializable(obj: Any) -> Any:
    """Convert class instances into dicts, dataclasses to dicts, etc."""

    if isinstance(obj, Enum):
        return obj.name
    elif isinstance(obj, BaseModel):
        return obj.model_dump()
    elif isinstance(obj, (list, tuple, Generator)):
        return [to_serializable(i) for i in obj]
    elif is_dataclass(obj):
        return to_serializable(asdict(obj))
    elif isinstance(obj, dict):
        return {k: to_serializable(v) for k, v in obj.items()}
    elif hasattr(obj, "__dict__"):
        return {k: to_serializable(v) for k, v in obj.__dict__.items() if not k.startswith("_")}
    
    return obj


def save_as_json(obj: Any, filepath: Path, print: bool = True) -> None:
    with open("w", filepath, encoding="utf-8") as f:
        json.dump(to_serializable(obj), f, ensure_ascii=False, indent=4)

    if print:
        console.print_info(f"File saved at {filepath}")        


def save_as_csv(obj: Any, filepath: Path, print: bool = True) -> None:
    obj = to_serializable(obj)

    with filepath.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        if isinstance(obj, list):
            if all(isinstance(item, dict) for item in obj):
                # List of dicts
                headers = sorted({k for d in obj for k in d.keys()})
                writer.writerow(headers)
                for d in obj:
                    writer.writerow([d.get(h, "") for h in headers])
            else:
                # List of primitives
                writer.writerow(["value"])
                for item in obj:
                    writer.writerow([item])
        elif isinstance(obj, dict):
            writer.writerow(["key", "value"])
            for k, v in obj.items():
                writer.writerow([k, v])
        else:
            writer.writerow(["value"])
            writer.writerow([obj])
    if print:
        console.print_info(f"File saved at {filepath}")


def expand_and_create_dir(path_str: str) -> Path:
    """
    Expand ~ and create the directory if it does not exist.
    """
    path = Path(path_str).expanduser()
    path.mkdir(parents=True, exist_ok=True)
    return path


# Dynamically build Click options
def add_enum_flags(enum_cls, help: Callable[[Enum], str]):
    def decorator(f):
        for member in enum_cls:
            value = member.value.lower()
            # Add a flag like --registrar
            f = click.option(
                f"--{value.replace('_','-')}",
                is_flag=True,
                help=help(value),
                default=False
            )(f)
        return f
    return decorator

def check_internet(throw: bool) -> bool:

    try:
        socket.create_connection(("1.1.1.1", 53), timeout=3)
        return True
    except Exception as e:
        print(e)
        if throw:
            raise InternetMissing()

    return False


