

import csv
import json
import click
from typosniffer.utils.console import console
from rich_click import RichCommand, RichGroup
from typosniffer.config import config
from typosniffer.fuzzing import fuzzer
from typosniffer.sniffing import sniffer
from typosniffer.utils.utility import validate_regex
from typeguard import typechecked
from dnstwist import VALID_FQDN_REGEX



def print_banner():
    banner = \
"""
████████╗██╗   ██╗██████╗  ██████╗                   
╚══██╔══╝╚██╗ ██╔╝██╔══██╗██╔═══██╗                  
   ██║    ╚████╔╝ ██████╔╝██║   ██║                  
   ██║     ╚██╔╝  ██╔═══╝ ██║   ██║                  
   ██║      ██║   ██║     ╚██████╔╝                  
   ╚═╝      ╚═╝   ╚═╝      ╚═════╝                   
                                                     
███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗ 
██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║
╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝

By Pierluigi Altimari                                                     

"""
    console.print(banner, style="bold green", highlight=False)

@typechecked
@click.group()
@click.option("-v", "--verbose", is_flag=True)
def cli(verbose: bool):
    print_banner()
    config.load()
    

@typechecked
@cli.command()
@click.option(
    '-f', '--format',
    type=click.Choice(fuzzer.POSSIBLE_FORMATS, case_sensitive=False),
    default=fuzzer.POSSIBLE_FORMATS[2],
    help='format of output file'
)
@click.argument('domain', callback=validate_regex(VALID_FQDN_REGEX, "not valid domain"))
@click.argument('filename', type=click.Path(dir_okay=True))
def fuzzing(filename: str, format: str, domain: str):

    format = format.lower()

    console.print("[bold green]Fuzzing Domain[/bold green]")
    
    with console.status("[bold green]Running Domain Fuzzing..[/bold green]"):
        with open(filename, "w", encoding="utf-8") as f:

            if format == 'json':
                output = dict()
                for permutation in fuzzer.fuzz(domain):
                    if permutation.fuzzer in output:
                        output[permutation.fuzzer].append(permutation.domain)
                    else:
                        output[permutation.fuzzer] = [permutation.domain]
                
                    json.dump(output, f, indent=4)
            elif format == "plain":
                domains = [permutation.domain for permutation in fuzzer.fuzz(domain)]
                f.write("\n".join(domains))
            elif format == "csv":
                writer = csv.DictWriter(f, fieldnames=["fuzzer", "domain"])
                for permutation in fuzzer.fuzz(domain):
                    writer.writerow(permutation)

@typechecked
@cli.command(help = "Using a set of DNS servers and a target domain, return all potential fuzzed subdomains or domain variations that can be resolved.")
@click.option(
    '-w', '--max_workers',
    type=int, 
    default= 10,
    help="Max numbers of threads used in paralled for dns queries"
)
@click.option(
    '-ns', '--nameserver',
    type=click.Path(exists=True),
    help='File containing a list of dns servers used for lookup in cycle'
)
@click.argument('domain', callback=validate_regex(VALID_FQDN_REGEX, "not valid domain"))
def sniff(max_workers: int, nameserver: list[str], domain: str):
    with console.status("[bold green]Sniffing potential similar domains[/bold green]"):
        sniffer.search_dns(domain, [], max_workers)


@cli.command(help = "Updates the tld dictionary from iana.org to generate all possible permutation using the fuzzer")
def tld():
    with console.status("[bold green]Updating tdl File[/bold green]"):
        fuzzer.update_tld_dictionary()

            

                                    
if __name__ == "__main__":
    cli()