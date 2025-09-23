import click

from rich.table import Table
from typosniffer.data.dto import DomainDTO
from typosniffer.service import website_record
from typosniffer.utils import console


@click.group()
def record():
    """Manage suspicious domain records"""


@record.command
@click.option('--order', '-o', type=click.Choice(['desc', 'asc']), show_default = True, default = 'asc', help="Order of records by creation date (asc or desc).")
@click.option('--limit', '-l', type=click.IntRange(min=0), default = 0)
@click.argument('suspicious_domain')
def list(suspicious_domain: str, order: str, limit: int):

    domain = DomainDTO(name = suspicious_domain)
    ascending = order == 'asc'
    records = website_record.get_suspicious_domain_records(domain, ascending, limit)
    
    if records:
        table = Table(title=f"{suspicious_domain} records")
        table.add_column("Id")
        table.add_column("Url")
        table.add_column("Creation Date")
        table.add_column("Status")

        for record in records:
            table.add_row(str(record.id), record.website_url, record.creation_date.isoformat(), record.status.name)

        console.print_info(table)
    else:
        console.print_info(f"Records not found for domain {suspicious_domain}")



