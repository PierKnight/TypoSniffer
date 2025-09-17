import click
from rich.table import Table
from pydantic import ValidationError
from typosniffer.utils import console
from typosniffer.config import config
from typeguard import typechecked
from typosniffer.cli.config import config as config_cli
from typosniffer.cli.domain import domain
from typosniffer.cli.discovery import discovery, clear
from typosniffer.cli.sniff import sniff
from typosniffer.cli.fuzzing import fuzzing
from typosniffer.cli.sus_domain import sus_domain


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


cli.add_command(config_cli)
cli.add_command(sus_domain)
cli.add_command(domain)
cli.add_command(sniff)
cli.add_command(clear)
cli.add_command(discovery)
cli.add_command(fuzzing)



if __name__ == "__init__":
    main()


