

from datetime import datetime
from enum import Enum
import json
import click
import rich
from rich.prompt import Confirm
from typosniffer.data.dto import DomainDTO, EntityType
from typosniffer.service import suspicious_domain as suspicious_domain_service, domain as domain_service
from typosniffer.utils import console

from typosniffer.utils.utility import to_serializable
from typosniffer.utils.utility import add_enum_flags

@click.group()
def sus_domain():
    """Manage suspicious domains"""

@sus_domain.command()
@add_enum_flags(EntityType, help=lambda value: f"Include {value} type")
@click.argument('domain')
def info(domain: str, **kwargs):
    """print detailed information about a suspicious domain"""

    selected_types = [etype for etype in EntityType if kwargs.get(etype.value.lower())]

    #if no entity type is selected use all of them by default
    if len(selected_types) == 0:
        selected_types = [t.value for t in EntityType]
    

    suspicious_domain = suspicious_domain_service.get_suspicious_domain(domain, selected_types)
    
    info = to_serializable(suspicious_domain)

    def json_serializer(obj):
        if isinstance(obj, datetime):
            return obj.isoformat() 
        if isinstance(obj, Enum):
            return obj.name
        raise TypeError(f"Type {type(obj)} not serializable")

    console.console.print_json(json.dumps(info, default=json_serializer, indent=4))


@sus_domain.command('list')
@click.argument('domain')
def domain_list(domain: str):
    """List all suspicious domains associated with a registered domain"""

    domain_dto = DomainDTO(name = domain)

    if not domain_service.exists(domain_dto):
        console.print_info(f"Domain not found, use 'typosniffer domain add {domain}' to register it")
        return

    suspicious_domains = suspicious_domain_service.get_suspicious_domains(domain_dto)

    if len(suspicious_domains) > 0:
        table = rich.table.Table(title="Suspicious Domains")
        table.add_column("Id", justify="left")
        table.add_column("Name", justify="right")

        for domain in suspicious_domains:
            table.add_row(str(domain.id), domain.name)  

        console.print_info(table)
    else:
        console.print_info(f"No suspicious domains were found for {domain}, use: 'typosniffer discovery' to update")

@sus_domain.command()
@click.argument('domains', nargs=-1)
def remove(domains: list[str]):
    """Remove suspicious domains"""

    with console.status("[bold green]Removing domains[/bold green]"):
        removed = suspicious_domain_service.remove_suspicious_domain(domains)
        console.print_info(f"Removed {removed} suspicious domains")

@sus_domain.command()
def clear():
    """Clear list of registered suspicious domains"""

    if Confirm.ask("[bold red]Are you sure you want to delete ALL registered suspicious domains?[/bold red]"):
        suspicious_domain_service.clear_suspicious_domains()
        console.print_info("✅ All suspicious domains deleted successfully.")
    else:
        console.print_warning("⚠️  Operation cancelled.")
