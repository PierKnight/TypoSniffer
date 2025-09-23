
from datetime import datetime, timedelta
import os
import click
from typosniffer.config.config import get_config
from typosniffer.service import domain, suspicious_domain
from typosniffer.sniffing import notification, whoisds, whoisfinder
from typosniffer.sniffing.monitor import inspect_domains
from typosniffer.utils import console
from apscheduler.schedulers.blocking import BlockingScheduler



@click.command(help = "Clear old whoisds domains")
@click.argument('days',type=click.IntRange(min=1))
def clear(days: int):
    with console.status("[bold green]Clearing old Domains[/bold green]"):
        removed_files = whoisds.clear_old_domains(max_days=days)
    console.print_info(f"[bold green]Cleared {removed_files} old domains[/bold green]")


@click.command()
@click.option('--force', is_flag=True, help='force scan even on already updated domains')
def discovery(
    force: bool
):  
    """Discover and save new suspicious domains by scanning whoisds.com latest registered domains"""
    domains = domain.get_domains()

    cfg = get_config().discovery

    start_date = datetime.now()


    if len(domains) == 0:
        console.print_info("Found 0 domains to scan, add domains using: typosniffer domain add")
        return
    
    criteria = cfg.criteria
    days = cfg.days
    clear_days = cfg.clear_days

    if clear_days is None:
        clear_days = cfg.days + 1

    #clear if max_days is set
    with console.status("Cleaning old Domains"):
        whoisds.clear_old_domains(clear_days)

    #update domains files
    domains_files = whoisds.update_domains(days, max_workers=cfg.updating_workers)

    #if force is true always check the domain files not only when updated
    if force:
        today = datetime.today()
        domains_files = [whoisds.WhoIsDsFile(today - timedelta(days=day+1)) for day in range(0, days)]
    
    if len(domains_files) > 0:

        #sniff new updated files to find typo squatting
        sniff_result = whoisds.sniff_whoisds(domains, criteria=criteria, whoisds_files=domains_files, max_workers=cfg.discovery_workers)
        
        #given the list of suspicious domains retrieve their respective whois data
        with console.status("[bold green]Retrieving whois data[/bold green]"):
            whois_data = whoisfinder.find_whois([sniff.domain for sniff in sniff_result], max_workers=cfg.whois_workers, requests_per_minute=cfg.requests_per_minute)
        with console.status("[bold green]Updating Suspicious Domains List[/bold green]"):
            suspicious_domain.add_suspicious_domain(sniff_result, whois_data)

        notification.notify_new_suspicious_domains(start_date, list(sniff_result))
    else:
        console.print_info("Force a new scan by using: --force")

@click.command()
def inspect():
    """Given all the registered suspicious domains, check if the website (if it exist) changed and run a similarity comparison against the real domain"""

    with console.status("Retrieving suspicious domain list"):
        domains = suspicious_domain.get_all_suspicious_domains()

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

    console.print_info("Starting Domain Discovery")

    #run discovery command
    ctx = click.Context(discovery)
    ctx.forward(discovery, force=False)

    console.print_info("Starting Domain Inspection")

    #run inspect command
    ctx = click.Context(inspect)
    ctx.forward(inspect)
            
@click.command()
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