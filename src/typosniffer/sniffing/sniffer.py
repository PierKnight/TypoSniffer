from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from itertools import cycle
from pathlib import Path
import dns
from dns import exception
from typeguard import typechecked
from typosniffer.data.dto import DomainDTO
from typosniffer.fuzzing import fuzzer
from typosniffer.utils.console import console
from dns import resolver
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
import textdistance
from typosniffer.utils.utility import strip_tld

@dataclass(frozen=True)
class SniffResult:
    original_domain: str = field(compare=True)
    domain: str = field(compare=True)
    dameraulevenshtein: int = field(compare=False)
    hamming: int = field(compare=False)
    jaro: float = field(compare=False)
    levenshtein: int = field(compare=False)

@dataclass(frozen=True)
class SniffCriteria:
    dameraulevenshtein: int
    hamming: int
    jaro: float
    levenshtein: int

@dataclass(frozen=True)
class SuspiciousDomainWhoIs:
    name: str
    original_domain: str
    data: dict
    

DEFAULT_CRITERIA = SniffCriteria(1, 1, 0.9, 1)




def resolve_domain(domain, nameserver):
    """Resolve using a specific DNS server."""

    #print(f"MAKE REQUEST {domain}")
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [nameserver]
    resolver.lifetime = 3
    resolver.timeout = 2
    answer = resolver.resolve(domain, "A")
    return [rdata.to_text() for rdata in answer]

@typechecked
def search_dns(domain: DomainDTO, tld_dictionary: list[str], word_dictionary: list[str], nameservers: list[str], max_workers=30):

    nameserver_cycle = cycle(nameservers)

    results = {}

    permutations = list(fuzzer.fuzz(domain, tld_dictionary=tld_dictionary, word_dictionary=word_dictionary))
    total_tasks = len(permutations)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {}

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("[green]{task.completed}/{task.total} domains resolved"),
            console=console
        ) as progress:
            task = progress.add_task("[green]Resolving domains...", total=total_tasks)


            for permutation in permutations:
                domain_name = permutation.domain
                future = executor.submit(resolve_domain, domain_name, next(nameserver_cycle))
                future_to_domain[future] = domain_name
                    
                
            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:

                    ips = future.result()
                    if ips:
                        results[domain] = ips
                except resolver.NXDOMAIN:
                    pass
                except exception.Timeout as e:
                    console.print(f"[bold red]Timeout with dns query: {domain}, {e}[/bold red]")
                except exception.DNSException as e:
                    console.print(f"[bold red]Something went wrong with dns query: {domain}, {e}[/bold red]")
                finally:
                    progress.update(task, advance=1)

    console.print("[bold green]DNS resolution completed![/bold green]")
    console.print(results)
                
    return results

def sniff_file(file: Path, domains: list[DomainDTO], criteria: SniffCriteria = DEFAULT_CRITERIA) -> set[SniffResult]:
    """
    Given a file, it will read every domain in them and perform checks for similarities with a domain/domains
    """
    results = set()
    with open(file, "r", encoding="utf-8") as f:
        for line in f:
                
                line = line.strip()

                for domain in domains:

                    _, original_domain = strip_tld(domain.name)
                    _, sniff_domain = strip_tld(line)

                    hamming = textdistance.hamming(original_domain, sniff_domain) if len(original_domain) == len(sniff_domain) else -1

                    sniff_result = SniffResult(
                        original_domain=domain.name,
                        domain=line,
                        dameraulevenshtein=textdistance.damerau_levenshtein(original_domain, sniff_domain),
                        hamming=hamming,
                        jaro=textdistance.jaro_winkler(original_domain, sniff_domain),
                        levenshtein=textdistance.levenshtein(original_domain, sniff_domain)
                    )
                
                    is_sus = sniff_result.hamming <= criteria.hamming and sniff_result.hamming >= 0 or \
                            sniff_result.dameraulevenshtein <= criteria.dameraulevenshtein or \
                            sniff_result.jaro >= criteria.jaro or \
                            sniff_result.levenshtein <= criteria.levenshtein

                    if is_sus:
                        results.add(sniff_result)
    return results

    
    






