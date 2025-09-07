

import csv
import json
import click
from typosniffer.sniffing import sniffer
from typosniffer.utils.console import console
from typosniffer.config import config
from typosniffer.fuzzing import fuzzer
from typosniffer.utils import utility
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

@click.group()
@click.option("-v", "--verbose", is_flag=True)
@typechecked
def cli(verbose: bool):
    print_banner()
    config.load()
    

@cli.command()
@click.option(
    '-tld', '--tld-dictionary',
    type=click.Path(exists=True),
    help='Top Level Domain list',
    callback=utility.list_file_option,
    default=utility.get_dictionary("tld.txt")
)
@click.option(
    '-wd', '--word-dictionary',
    type=click.Path(exists=True),
    help='Word Dictionary to use',
    callback=utility.list_file_option,
    default=utility.get_dictionary("words.txt")
)
@click.option(
    '-f', '--format',
    type=click.Choice(fuzzer.POSSIBLE_FORMATS, case_sensitive=False),
    default=fuzzer.POSSIBLE_FORMATS[2],
    help='format of output file'
)
@click.argument('domain', callback=utility.validate_regex(VALID_FQDN_REGEX, "not valid domain"))
@click.argument('filename', type=click.Path(dir_okay=True))
@typechecked
def fuzzing(tld_dictionary: list[str], word_dictionary: list[str], filename: str, format: str, domain: str):

    format = format.lower()

    console.print("[bold green]Fuzzing Domain[/bold green]")
    
    with console.status("[bold green]Running Domain Fuzzing..[/bold green]"):
        with open(filename, "w", encoding="utf-8") as f:

            if format == 'json':
                output = dict()
                for permutation in fuzzer.fuzz(domain, tld_dictionary, word_dictionary):
                    if permutation.fuzzer in output:
                        output[permutation.fuzzer].append(permutation.domain)
                    else:
                        output[permutation.fuzzer] = [permutation.domain]
                json.dump(output, f, indent=4)
            elif format == "plain":
                domains = [permutation.domain for permutation in fuzzer.fuzz(domain, tld_dictionary, word_dictionary)]
                f.write("\n".join(domains))
            elif format == "csv":
                writer = csv.DictWriter(f, fieldnames=["fuzzer", "domain"])
                for permutation in fuzzer.fuzz(domain, tld_dictionary, word_dictionary):
                    writer.writerow(permutation)

@cli.command(help = "Using a set of DNS servers and a target domain, return all potential fuzzed subdomains or domain variations that can be resolved.")
@click.option(
    '-w', '--max_workers',
    type=int, 
    default= 10,
    help="Max numbers of threads used in paralled for dns queries"
)
@click.option(
    '-ns', '--nameservers',
    type=click.Path(exists=True),
    help='File containing a list of dns servers used for lookup in cycle',
    callback=utility.list_file_option,
    default=utility.get_dictionary("nameservers.txt")
)
@click.option(
    '-tld', '--tld-dictionary',
    type=click.Path(exists=True),
    help='Top Level Domain list',
    callback=utility.list_file_option,
    default=utility.get_dictionary("tld.txt")
)
@click.option(
    '-wd', '--word-dictionary',
    type=click.Path(exists=True),
    help='Word Dictionary to use',
    callback=utility.list_file_option,
    default=utility.get_dictionary("words.txt")
)
@click.argument('domain', callback=utility.validate_regex(VALID_FQDN_REGEX, "not valid domain"))
@typechecked
def sniff(tld_dictionary: list[str], word_dictionary: list[str], nameservers: list[str], max_workers: int, domain: str):
    with console.status("[bold green]Sniffing potential similar domains[/bold green]"):
        sniffer.search_dns(domain, tld_dictionary=tld_dictionary, word_dictionary=word_dictionary, nameservers=nameservers, max_workers=max_workers)


@cli.command(help = "Updates the tld dictionary from iana.org to generate all possible permutation using the fuzzer")
def tld():
    with console.status("[bold green]Updating tdl File[/bold green]"):
        fuzzer.update_tld_dictionary()
    

                                    
if __name__ == "__main__":
    cli()