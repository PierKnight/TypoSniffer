from pathlib import Path
import click
import imagehash
from rich.table import Table
from pydantic import ValidationError
from typosniffer.utils import console
from typosniffer.config import config
from typeguard import typechecked
from typosniffer.cli.domain import domain
from typosniffer.cli.scan import scan, clear
from typosniffer.cli.sniff import sniff
from typosniffer.cli.fuzzing import fuzzing
from typosniffer.cli.sus_domain import sus_domain
from PIL import Image


def print_banner():
    banner = \
"""
████████╗██╗   ██╗██████╗  ██████╗                   
╚══██╔══╝╚██╗ ██╔╝██╔══██╗██╔═══██╗                  
   ██║    ╚████╔╝ ██████╔╝██║   ██║                  
   ██║     ╚██╔╝  ██╔═══╝ ██║   ██║                  
   ██║      ██║   ██║     ╚██████╔╝                  
   ╚═╝      ╚═╝   ╚═╝      ╚═════╝                   
                                                     
███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗ 
██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║
╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝

By Pierluigi Altimari                                                     

"""
    console.print_info(f"[bold green]{banner}[/bold green]")


@click.group()
@click.option("-v", "--verbose", is_flag=True)
@typechecked
def cli(verbose: bool):
    print_banner()

def main():
    try:
        config.load()
        cli()

    except ValidationError as e:
        table = Table(title="Validation Errors")
        table.add_column("Field", style="cyan")
        table.add_column("Error", style="red")
        table.add_column("Value", style="yellow")

        for err in e.errors():
            field = ".".join(map(str, err["loc"]))
            table.add_row(field, err["msg"], str(err.get("input")))

        console.print_info(table)
    except Exception:
        console.console.print_exception()
        return None


@cli.command
@click.argument("file1", type=click.Path(file_okay=True))
@click.argument("file2", type=click.Path(file_okay=True))
def compare(file1: Path, file2: Path):

    hash_def = imagehash.dhash

    size = 64

    hash1 = hash_def(Image.open(file1), hash_size=size)
    hash2 = hash_def(Image.open(file2), hash_size=size)

    hash1 = imagehash.hex_to_hash(str(hash1))
    hash2 = imagehash.hex_to_hash(str(hash2))

    print(f"SIMILARITY {1 - (hash2 - hash1) / (size * 8)}")



cli.add_command(sus_domain)
cli.add_command(domain)
cli.add_command(sniff)
cli.add_command(clear)
cli.add_command(scan)
cli.add_command(fuzzing)



if __name__ == "__init__":
    main()


