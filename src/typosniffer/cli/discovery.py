
from datetime import datetime, timedelta
import click
from typosniffer.config.config import get_config
from typosniffer.service import domain, suspicious_domain
from typosniffer.sniffing import notification, whoisds, whoisfinder
from typosniffer.utils import console



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
    """"Discover and save new suspicious domains by scanning whoisds.com latest registered domains"""
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
