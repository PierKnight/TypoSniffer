
from datetime import datetime, timedelta
import click
from typosniffer.service import domain, suspicious_domain
from typosniffer.sniffing import sniffer, whoisds, whoisfinder
from typosniffer.utils import console


@click.command(help = "Clear old whoisds domains")
@click.argument('days',type=click.IntRange(min=1))
def clear(days: int):
    with console.status("[bold green]Clearing old Domains[/bold green]"):
        removed_files = whoisds.clear_old_domains(max_days=days)
    console.print_info(f"[bold green]Cleared {removed_files} old domains[/bold green]")


@click.command()
@click.option('-d', '--days', envvar="SNIFF_DAYS", type=click.IntRange(min=1), default=1, help='Max days to update whoisds files')
@click.option('-c', '--clear-days', envvar="SNIFF_CLEAR_DAYS", type=click.IntRange(min=0), default=0, help='Clear whoisds domains older that this number of days')
@click.option('--damerau-levenshtein', envvar="SNIFF_DAMERAU_LEVENSHTEIN", default=1, help='Override default dameraulevenshtein.')
@click.option('--hamming', envvar="SNIFF_HAMMING", default=None, help='Override default hamming.')
@click.option('--jaro', envvar="SNIFF_JARO", default=None, help='Override default jaro.')
@click.option('--jaro-winkler', envvar="SNIFF_JARO_WINKLER", default=0.9, help='Override default jaro-winkler.')
@click.option('--tf-idf', envvar="SNIFF_TDF_IDF", default=None, help='Override default tdf_idf.')
@click.option('--levenshtein', envvar="SNIFF_LEVENSHTEIN", default=1, help='Override default levenshtein.')
@click.option('--force', is_flag=True, help='force scan even on already updated domains')
def scan(
    days: int,
    clear_days: int,
    damerau_levenshtein: int, 
    hamming: int,
    jaro: float,
    levenshtein: int,
    jaro_winkler: float,
    tf_idf: float,
    force: bool
):  
    """"Update And Scan Domains collected from whoisds.com"""
    domains = domain.get_domains()


    if len(domains) == 0:
        console.print_info("Found 0 domains to scan, add domains using: typosniffer domain add")
        return
    
    #setup criteria used for identifying suspicious domains
    criteria = sniffer.SniffCriteria(
        damerau_levenshtein=damerau_levenshtein,
        hamming=hamming,
        jaro=jaro,
        jaro_winkler=jaro_winkler,
        levenshtein=levenshtein,
        tf_idf=tf_idf
    )

    if clear_days == 0:
        clear_days = days + 1

    #clear if max_days is set
    with console.status("Cleaning old Domains"):
        whoisds.clear_old_domains(clear_days)

    #update domains files
    domains_files = whoisds.update_domains(days, max_workers=10)

    #if force is true always check the domain files not only when updated
    if force:
        today = datetime.today()
        domains_files = [whoisds.WhoIsDsFile(today - timedelta(days=day+1)) for day in range(0, days)]
    
    if len(domains_files) > 0:

        #sniff new updated files to find typo squatting
        sniff_result = whoisds.sniff_whoisds(domains, criteria=criteria, whoisds_files=domains_files)
                
        #given the list of suspicious domains retrieve their respective whois data
        with console.status("[bold green]Retrieving whois data[/bold green]"):
            whois_data = whoisfinder.find_whois([sniff.domain for sniff in sniff_result])
        with console.status("[bold green]Updating Suspicious Domains List[/bold green]"):
            suspicious_domain.add_suspicious_domain(sniff_result, whois_data)
    else:
        console.print_info("Force a new scan by using: --force")
