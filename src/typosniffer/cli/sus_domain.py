

import click

from typosniffer.service import suspicious_domain
from typosniffer.sniffing.monitor import monitor_domains
from typosniffer.utils import console


@click.group()
def sus_domain():
    """Manage suspicious domains"""


@sus_domain.command()
@click.option('-w', '--max-workers', default= 4, type=click.IntRange(min=1))
def monitor(max_workers: int):

    with console.status("Retrieving suspicious domain list"):
        domains = suspicious_domain.get_suspicious_domains()

    if len(domains) == 0:
        console.print_info("No suspicious domains have been found: use 'typosniffer scan' to update the list")
        return


    monitor_domains(domains, max_workers)