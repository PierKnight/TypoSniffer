
import click
from rich.prompt import Confirm
from typosniffer.data import service
from typosniffer.data.dto import DomainDTO
from typosniffer.utils.console import console


@click.group()
def domain():
    """Manage domains"""

@domain.command()
@click.argument('names', nargs=-1)
def add(names):
    """Add a new domain"""
    domains = [DomainDTO(name = name) for name in names]

    service.add_domains(domains)

@domain.command()
@click.argument('names', nargs=-1)
def remove(names):
    """Remove an existing domain"""
    domains = [DomainDTO(name = name) for name in names]
    removed = service.remove_domains(domains)
    console.print(f"Removed {removed} domains")

@domain.command()
def list():
    """Get list of registered domains"""
    domains = service.get_domains()
    for domain in domains:
        console.print(f"{domain.name}")

@domain.command()
def clear():
    """Clear list of registered domains"""

    if Confirm.ask("[bold red]Are you sure you want to delete ALL registered domains?[/bold red]"):
        service.clear_domains()
        console.print("[green]✅ All domains deleted successfully.[/green]")
    else:
        console.print("[yellow]⚠️ Operation cancelled.[/yellow]")
