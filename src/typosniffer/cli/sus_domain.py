

import click

from typosniffer.config.config import get_config
from typosniffer.service import suspicious_domain
from typosniffer.sniffing.monitor import inspect_domains
from typosniffer.utils import console


@click.group()
def sus_domain():
    """Manage suspicious domains"""


@sus_domain.command()
def inspect():

    with console.status("Retrieving suspicious domain list"):
        domains = suspicious_domain.get_suspicious_domains()

    if len(domains) == 0:
        console.print_info("No suspicious domains have been found: use 'typosniffer scan' to update the list")
        return

    cfg = get_config()

    with console.status("Inspecting suspicious domains"):
        domains = suspicious_domain.get_suspicious_domains()
        inspect_domains(domains, cfg.monitor.max_workers)