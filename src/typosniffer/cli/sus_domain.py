

from datetime import datetime
import click
from typosniffer.config.config import get_config
from typosniffer.service import suspicious_domain
from typosniffer.sniffing import notification
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

    start_date = datetime.now()

    with console.status("Inspecting suspicious domains"):
        domains = suspicious_domain.get_suspicious_domains()
        reports = inspect_domains(domains, cfg.monitor.max_workers)

        for report in reports:
            domain = report.suspicious_domain
            if report.update_report:
                console.print_info(f"Domain {domain.name} updated: {report.update_report}")
            if report.phishing_report:
                console.print_info(f"Domain {domain.name} phishing scan: {report.phishing_report}")
            if report.error_msg:
                console.print_error(report.error_msg)

        
    notification.notify_inspection_suspicious_domains(inspection_date=start_date, reports=reports, suspicious_domains=domains)
            
            
