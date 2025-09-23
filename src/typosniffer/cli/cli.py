import logging
from typosniffer.utils.click_utility import LoggingGroup
from typosniffer.utils.logger import log
import click
from rich.table import Table
from pydantic import ValidationError
from typosniffer.utils import console
from typosniffer.config import config
from typeguard import typechecked
from typosniffer.cli.config import config as config_cli
from typosniffer.cli.domain import domain
from typosniffer.cli.monitor import discovery, inspect, monitor
from typosniffer.cli.tools import tools
from typosniffer.cli.sus_domain import sus_domain
from typosniffer.cli.test import test
from typosniffer.cli.record import record


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


@click.group(invoke_without_command=True, cls=LoggingGroup)
@click.option("-v", "--verbose", is_flag=True)
@click.pass_context
@typechecked
def cli(ctx : click.core.Context, verbose: bool):

    if verbose:
        log.setLevel(logging.DEBUG)

    if ctx.invoked_subcommand is None:
        print_banner()
        click.echo(cli.get_help(ctx))

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
        log.error('Generic Error in Cli', exc_info=True)
        return None

cli.add_command(config_cli)
cli.add_command(discovery)
cli.add_command(inspect)
cli.add_command(monitor)
cli.add_command(sus_domain)
cli.add_command(domain)
cli.add_command(tools)
cli.add_command(test)
cli.add_command(record)


if __name__ == "__init__":
    main()


