import click
from typosniffer.data.dto import DomainDTO
from typosniffer.sniffing import sniffer
from typosniffer.utils import utility
from typosniffer.utils import console


@click.command()
@click.option(
    '-w', '--max_workers',
    type=int, 
    default=40,
    help="Max numbers of threads used in paralled for dns queries"
)
@click.option(
    '-ns', '--nameservers',
    type=click.Path(exists=True),
    help='File containing a list of dns servers used for lookup in cycle',
    callback=utility.list_file_option,
    default=utility.get_resource("nameservers.txt")
)
@click.option(
    '-tld', '--tld-dictionary',
    type=click.Path(exists=True),
    help='Top Level Domain list',
    callback=utility.list_file_option,
    default=utility.get_resource("tld.txt")
)
@click.option(
    '-wd', '--word-dictionary',
    type=click.Path(exists=True),
    help='Word Dictionary to use',
    callback=utility.list_file_option,
    default=utility.get_resource("words.txt")
)
@click.option('-o', '--output', type=click.Path(dir_okay=True, writable=True), help='File to write results')
@click.argument('domain')
def sniff(tld_dictionary: list[str], word_dictionary: list[str], nameservers: list[str], max_workers: int, output: str | None, domain: str):
    """Using a set of DNS servers and a target domain, return all potential fuzzed subdomains or domain variations that can be resolved"""
    
    domain_dto = DomainDTO(name=domain)
    
    with console.status("[bold green]Sniffing potential similar domains[/bold green]"):
        results = sniffer.search_dns(domain_dto, tld_dictionary=tld_dictionary, word_dictionary=word_dictionary, nameservers=nameservers, max_workers=max_workers)
    
    console.print_info("[bold green]DNS resolution completed![/bold green]")
    console.print_info(results)
    
    if output:
        utility.save_as_json(results, output)

