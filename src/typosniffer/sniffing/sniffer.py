from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from itertools import cycle
from pathlib import Path
import dns
from dns import exception
from typosniffer.data.dto import DomainDTO
from typosniffer.data.dto import SniffCriteria
from typosniffer.sniffing import fuzzer
from typosniffer.sniffing import tf_idf
from typosniffer.utils import console
from typosniffer.utils.logger import log
from dns import resolver
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
import textdistance
from typosniffer.utils.utility import strip_tld
import numpy


@dataclass(frozen=True)
class SniffResult:
    original_domain: str
    domain: str
    suspicious: bool
    damerau_levenshtein: int
    hamming: int
    jaro: float
    jaro_winkler: float
    levenshtein: int
    tf_idf: float

@dataclass(frozen=True)
class SuspiciousDomainWhoIs:
    name: str
    original_domain: str
    data: dict
    


SNIFF_ALGORITHMS = {
    'damerau_levenshtein': {'alg': textdistance.damerau_levenshtein, 'check': 'lower'},
    'levenshtein': {'alg': textdistance.levenshtein, 'check': 'lower'},
    'hamming': {'alg': textdistance.hamming, 'check': 'lower'},
    'jaro': {'alg': textdistance.jaro, 'check': 'upper'},
    'jaro_winkler': {'alg': textdistance.jaro_winkler, 'check': 'upper'},
    'tf_idf': {'alg': tf_idf.cosine_similarity_string, 'check': 'upper'}
}


def compare_domain(original_domain: str, domain: str, criteria: SniffCriteria) -> SniffResult:


    _, original_sub_domain = strip_tld(original_domain)
    _, sub_domain = strip_tld(domain)

    sniff_result = {}
    sus = False

    for name, algorithm_info in SNIFF_ALGORITHMS.items():
        criteria_value = getattr(criteria, name)
        value = algorithm_info['alg'](original_sub_domain, sub_domain)

        if criteria_value:
            suspicious = value > criteria_value if algorithm_info['check'] == 'upper' else value < criteria_value
            if suspicious:
                sus = True
        sniff_result[name] = value

    return SniffResult(domain=domain, original_domain=original_domain, suspicious=sus, **sniff_result)





def resolve_domain(domain, nameserver):
    """Resolve using a specific DNS server."""
    #print(f"MAKE REQUEST {domain}")
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [nameserver]
    resolver.lifetime = 3
    resolver.timeout = 2
    answer = resolver.resolve(domain, "A")
    return [rdata.to_text() for rdata in answer]

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
            console=console.console
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
                    console.print_error(f"[bold red]Timeout with dns query: {domain}, {e}[/bold red]")
                    log.error("Dns Query Timeout", exc_info=True)
                except exception.DNSException as e:
                    console.print_error(f"[bold red]Something went wrong with dns query: {domain}, {e}[/bold red]")
                    log.error(f"Dns Query Exception: {domain}", exc_info=True)
                finally:
                    progress.update(task, advance=1)
                
    return results

def scan_domains(chunk: list[str], domains: list[DomainDTO], criteria: SniffCriteria) -> set[SniffResult]:

    results = set()
    for domain_to_scan in chunk:
        for domain in domains:
                
            sniff_result = compare_domain(domain.name, domain_to_scan, criteria)

            if sniff_result.suspicious:
                results.add(sniff_result)
    return results

def sniff_file(file: Path, domains: list[DomainDTO], criteria: SniffCriteria, max_workers: int) -> set[SniffResult]:
    """
    Given a file, it will read every domain in them and perform checks for similarities with a domain/domains
    """


    log.info(f"Sniffing file {file}")

    with open(file, "r") as f:
        domains_to_scan = [line.strip() for line in f.readlines()]

    chunks = numpy.array_split(numpy.array(domains_to_scan), max_workers)

    with ProcessPoolExecutor(max_workers=len(chunks)) as executor:
        futures = [executor.submit(scan_domains, chunk, domains, criteria) for chunk in chunks]

    results = set()

    processed_chunks = 0

    for future in futures:
        try:
            results.update(future.result())
            processed_chunks += 1
            log.info(f"sniffed chunk {processed_chunks}/{max_workers}")
        except Exception:
            log.error(f"Failed scanning chunk of domain {file}", exc_info=True)

    log.info(f"sniffed a total of {len(domains_to_scan)} domains")
    
    return results

    
    






