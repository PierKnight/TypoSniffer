

from datetime import datetime
from enum import Enum
import json
import os
import click
import rich
from rich.prompt import Confirm
from typosniffer.cli import discovery
from typosniffer.config.config import get_config
from typosniffer.data.dto import DomainDTO, EntityType
from typosniffer.service import suspicious_domain as suspicious_domain_service, domain as domain_service
from typosniffer.sniffing import notification
from typosniffer.sniffing.monitor import inspect_domains
from typosniffer.utils import console
from apscheduler.schedulers.blocking import BlockingScheduler

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

@sus_domain.command()
def inspect():
    """Given all the registered suspicious domains, check if the website (if it exist) changed and run a similarity comparison against the real domain"""

    with console.status("Retrieving suspicious domain list"):
        domains = suspicious_domain_service.get_all_suspicious_domains()

    if len(domains) == 0:
        console.print_info("No suspicious domains have been found: use 'typosniffer discovery' to update the list")
        return

    cfg = get_config()

    start_date = datetime.now()

    with console.status("Inspecting suspicious domains"):
        reports = inspect_domains(domains, cfg.inspection.max_workers)

        for report in reports:
            domain = report.suspicious_domain
            if report.update_report:
                console.print_info(f"Domain {domain.name} updated: {report.update_report}")
            if report.phishing_report:
                console.print_info(f"Domain {domain.name} phishing scan: {report.phishing_report}")
        
    notification.notify_inspection_suspicious_domains(inspection_date=start_date, reports=reports, suspicious_domains=domains)


def _monitor_task():
    #run discovery command
    ctx = click.Context(discovery.discovery)
    ctx.forward(discovery.discovery, force=False)

    #run inspect command
    ctx = click.Context(inspect)
    ctx.forward(inspect)
            
@sus_domain.command()
@click.argument('hour')
@click.argument('minute')
def monitor(hour: str, minute: str):
    """Daemon to monitor suspicious domains by calling the discovery and inspection step each day"""

    scheduler = BlockingScheduler()

    try:
        scheduler.add_job(_monitor_task, 'cron', hour=hour, minute=minute)
        console.print_info("Press Ctrl+{} to exit".format("Break" if os.name == "nt" else "C"))
        scheduler.start()
    except ValueError as e:
        console.print_error(e)