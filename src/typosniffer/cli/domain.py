
import click
from rich.prompt import Confirm
from typosniffer.data.dto import DomainDTO
from typosniffer.utils import console
from typosniffer.utils.exceptions import ServiceFailure
from typosniffer.service.domain import *


@click.group()
def domain():
    """Manage domains"""

@domain.command()
@click.argument('names', nargs=-1)
def add(names):
    """Add a new domain"""
    domains = [DomainDTO(name = name) for name in names]

    with console.status("[bold green]Adding domains[/bold green]"):
        try:
            add_domains(domains)
            console.print_info(f"Successfully added {len(domains)} domains")
        except ServiceFailure as e:
            console.print_error(e)

@domain.command()
@click.argument('names', nargs=-1)
def remove(names):
    """Remove an existing domain"""
    domains = [DomainDTO(name = name) for name in names]

    with console.status("[bold green]Removing domains[/bold green]"):
        removed = remove_domains(domains)
        console.print_info(f"Removed {removed} domains")

@domain.command()
def list():
    """Get list of registered domains"""

    with console.status("[bold green]Retrieving domain list[/bold green]"):
        domains = get_domains()
        for domain in domains:
            console.print_info(f"{domain.name}")

@domain.command()
def clear():
    """Clear list of registered domains"""

    if Confirm.ask("[bold red]Are you sure you want to delete ALL registered domains?[/bold red]"):
        clear_domains()
        console.print_info("✅ All domains deleted successfully.")
    else:
        console.print_warning("⚠️  Operation cancelled.")
