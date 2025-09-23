from pathlib import Path
import click
from typosniffer.data.dto import DomainDTO
from typosniffer.sniffing import fuzzer, sniffer
from typosniffer.utils import utility
from typosniffer.utils import console
from typosniffer.utils.click_utility import LoggingGroup


@click.group(cls=LoggingGroup)
def tools():
    """additional tools"""


@tools.command()
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
def dns(tld_dictionary: list[str], word_dictionary: list[str], nameservers: list[str], max_workers: int, output: str | None, domain: str):
    """Using a set of DNS servers and a target domain, return all potential fuzzed subdomains or domain variations that can be resolved"""
    
    domain_dto = DomainDTO(name=domain)
    
    with console.status("[bold green]Sniffing potential similar domains[/bold green]"):
        results = sniffer.search_dns(domain_dto, tld_dictionary=tld_dictionary, word_dictionary=word_dictionary, nameservers=nameservers, max_workers=max_workers)
    
    console.print_info("[bold green]DNS resolution completed![/bold green]")
    console.print_info(results)
    
    if output:
        utility.save_as_json(results, output)

@tools.command()
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
@click.option('-f', '--format', type=click.Choice(['csv', 'json'], case_sensitive=False), default='csv', help='format of output file')
@click.option('-u', '--unicode', is_flag=True, default=False, help='Write domains in unicode instead of punycode')
@click.argument('domain')
@click.argument('filename', type=click.Path(dir_okay=True, writable=True))
def fuzzing(unicode: bool, tld_dictionary: list[str], word_dictionary: list[str], filename: str, format: str, domain: str):
    """Generate possible permutations of a given domain used in typosquatting"""
    format = format.lower()

    domain_dto = DomainDTO(name=domain)

    with console.status("[bold green]Running Domain Fuzzing..[/bold green]"):
        file_path = Path(filename).resolve()

        fuzz_generator = fuzzer.fuzz(domain_dto, tld_dictionary, word_dictionary, unicode)

        if format == 'json':

            output = {}
            for permutation in fuzz_generator:
                output.setdefault(permutation.fuzzer, []).append(permutation.domain)

            utility.save_as_json(output, file_path)
        elif format == 'csv':
            utility.save_as_csv(fuzz_generator, file_path)
        else:
            console.print_error(f"Unknown format: {format}. Supported: json, plain, csv")
            return