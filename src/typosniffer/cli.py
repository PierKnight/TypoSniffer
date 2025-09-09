

import csv
from dataclasses import asdict
import json
import click
from typosniffer.sniffing import sniffer
from typosniffer.sniffing.whoisfinder import find_whois
from typosniffer.utils.console import console
from typosniffer.config import config
from typosniffer.fuzzing import fuzzer
from typosniffer.utils import utility
from typosniffer.whoisds import whoisds
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
    

@cli.command(help="Generate possible permutations of a given domain used in typosquatting")
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
@click.option('-f', '--format', type=click.Choice(fuzzer.POSSIBLE_FORMATS, case_sensitive=False), default=fuzzer.POSSIBLE_FORMATS[2], help='format of output file')
@click.argument('domain', callback=utility.validate_regex(VALID_FQDN_REGEX, "not valid domain"))
@click.argument('filename', type=click.Path(dir_okay=True, writable=True))
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
    default=40,
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
@click.option('-o', '--output', type=click.Path(dir_okay=True, writable=True), help='File to write results')
@click.argument('domain', callback=utility.validate_regex(VALID_FQDN_REGEX, "not valid domain"))
@typechecked
def sniff(tld_dictionary: list[str], word_dictionary: list[str], nameservers: list[str], max_workers: int, output: str | None, domain: str):
    with console.status("[bold green]Sniffing potential similar domains[/bold green]"):
        results = sniffer.search_dns(domain, tld_dictionary=tld_dictionary, word_dictionary=word_dictionary, nameservers=nameservers, max_workers=max_workers)
        if output:
            with open(output, "w") as f:
                json.dump(results, f, indent=4)

@cli.command(help = "Clear old whoisds domains")
@click.argument('days',type=click.IntRange(min=1))
def clear(days: int):
    with console.status("[bold green]Clearing old Domains[/bold green]"):
        removed_files = whoisds.clear_old_domains(max_days=days)
    console.print(f"[bold green]Cleared {removed_files} old domains[/bold green]")


@cli.command(help = "Update And Scan Domains collected from whoisds.com")
@click.option('-d', '--days', type=click.IntRange(min=1), default=30, help='Max days to update whoisds files')
@click.option('-c', '--clear-days', type=click.IntRange(min=0), default=0, help='Clear whoisds domains older that this number of days')
@click.argument('domain', callback=utility.validate_regex(VALID_FQDN_REGEX, "not valid domain"))
@click.option('--dameraulevenshtein', type=click.IntRange(min=0), default=None, help='Override default dameraulevenshtein.')
@click.option('--hamming', type=click.IntRange(min=0), default=None, help='Override default hamming.')
@click.option('--jaro', type=click.FloatRange(min=0, max=1), default=None, help='Override default jaro.')
@click.option('--levenshtein', type=click.IntRange(min=0), default=None, help='Override default levenshtein.')
@click.option('-o', '--output',type=click.Path(dir_okay=True, writable=True), help='File to write results')
@click.option('-f', '--format', type=click.Choice(['csv', 'json'], case_sensitive=False), default='json', help='format of output file')
def scan(
    days: int,
    clear_days: int,
    domain: str,
    dameraulevenshtein: int, 
    hamming: int,
    jaro: float,
    levenshtein: int,
    output: str | None,
    format: str
):
    criteria = sniffer.SniffCriteria(
        dameraulevenshtein=dameraulevenshtein if dameraulevenshtein is not None else sniffer.DEFAULT_CRITERIA.dameraulevenshtein,
        hamming=hamming if hamming is not None else sniffer.DEFAULT_CRITERIA.hamming,
        jaro=jaro if jaro is not None else sniffer.DEFAULT_CRITERIA.jaro,
        levenshtein=levenshtein if levenshtein is not None else sniffer.DEFAULT_CRITERIA.levenshtein,
    )

    sniff_result = whoisds.whoisds_cli(domain, update_days=days, max_days=clear_days, criteria=criteria)

    if output:
        if format == "json":
            with open(output, "w") as f:
                json.dump([asdict(sniff) for sniff in sniff_result], f, indent=4)
        elif(format == "csv"):
            with open(output, "w") as f:
                writer = csv.writer(f)
                writer.writerow(["domain", "dameraulevenshtein", "hamming", "jaro", "levenshtein"])
                for sniff in sniff_result:
                    writer.writerow([sniff.domain, sniff.dameraulevenshtein, sniff.hamming, sniff.jaro, sniff.levenshtein])
    
    with console.status("[bold green]Retrieving whois data[/bold green]"):
        print(find_whois([sniff.domain for sniff in sniff_result]))

            
    

@cli.command
def test():
    print(find_whois(["google.com"]))


                                    
if __name__ == "__main__":
    cli()