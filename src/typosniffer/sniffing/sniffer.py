from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from multiprocessing import Process, Queue
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
    


# Mapping of domain similarity algorithms with their threshold check type
SNIFF_ALGORITHMS = {
    'damerau_levenshtein': {'alg': textdistance.damerau_levenshtein, 'check': 'lower'},
    'levenshtein': {'alg': textdistance.levenshtein, 'check': 'lower'},
    'hamming': {'alg': textdistance.hamming, 'check': 'lower'},
    'jaro': {'alg': textdistance.jaro, 'check': 'upper'},
    'jaro_winkler': {'alg': textdistance.jaro_winkler, 'check': 'upper'},
    'tf_idf': {'alg': tf_idf.cosine_similarity_string, 'check': 'upper'}
}

def compare_domain(original_domain: str, domain: str, criteria: SniffCriteria) -> SniffResult:
    """
    Compares a domain against an original domain using multiple algorithms defined in SNIFF_ALGORITHMS.
    Determines if the domain is suspicious based on the provided SniffCriteria thresholds.
    """

    # Remove TLDs to focus comparison on the main subdomain part
    _, original_sub_domain = strip_tld(original_domain)
    _, sub_domain = strip_tld(domain)

    sniff_result = {}
    sus = False  # Flag to indicate if domain is suspicious

    # Iterate over each algorithm and compute similarity/distance
    for name, algorithm_info in SNIFF_ALGORITHMS.items():
        criteria_value = getattr(criteria, name)
        
        value = None

        # Only mark as suspicious if the computed value crosses the threshold
        if criteria_value:
            value = algorithm_info['alg'](original_sub_domain, sub_domain)
            suspicious = value > criteria_value if algorithm_info['check'] == 'upper' else value < criteria_value
            if suspicious:
                sus = True

        sniff_result[name] = value  # store score for this algorithm

    # Return aggregated result with all algorithm scores and suspicious flag
    return SniffResult(domain=domain, original_domain=original_domain, suspicious=sus, **sniff_result)



def resolve_domain(domain, nameserver):
    """Resolve using a specific DNS server."""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [nameserver]
    resolver.lifetime = 4
    resolver.timeout = 3
    answer = resolver.resolve(domain, "A")
    return [rdata.to_text() for rdata in answer]

def search_dns(
    domain: DomainDTO,
    tld_dictionary: list[str],
    word_dictionary: list[str],
    nameservers: list[str],
    max_workers=30
):
    """
    Perform DNS resolution for a list of domain permutations generated from a base domain.
    
    Parameters:
    - domain: DomainDTO object representing the base domain to fuzz.
    - tld_dictionary: List of top-level domains to try (e.g., ['com', 'net']).
    - word_dictionary: List of words to insert into the domain permutations.
    - nameservers: List of DNS servers to use for resolution.
    - max_workers: Maximum number of threads for concurrent DNS resolution.

    Returns:
    - A dictionary mapping domain names to a list of resolved IP addresses.
    """

    # Rotate through the given nameservers to distribute DNS queries evenly
    nameserver_cycle = cycle(nameservers)

    # Store successful DNS resolution results
    results = {}

    # Generate all domain permutations using the fuzzer
    permutations = list(fuzzer.fuzz(
        domain, 
        tld_dictionary=tld_dictionary, 
        word_dictionary=word_dictionary
    ))
    total_tasks = len(permutations)  # total number of DNS queries to perform

    # Use a ThreadPoolExecutor for concurrent DNS queries
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {}  # map futures to domain names for later retrieval

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
                    # Get the resolved IPs from the future
                    ips = future.result()
                    if ips:
                        results[domain] = ips 
                except resolver.NXDOMAIN:
                    pass
                except exception.Timeout as e:
                    console.print_error(f"[bold red]Timeout with dns query: {domain}, {e}[/bold red]")
                except exception.DNSException as e:
                    console.print_error(f"[bold red]Something went wrong with dns query: {domain}, {e}[/bold red]")
                    log.error(f"Dns Query Exception: {domain}", exc_info=True)
                finally:
                    progress.update(task, advance=1)
                
    return results


def _scan_domains(
    task_id: int,
    chunk: list[str],
    domains: list[DomainDTO],
    criteria: SniffCriteria,
    queue: Queue
):
    """
    Worker function that scans a chunk of domains against a list of reference domains
    and sends progress updates and results back to the main process via a multiprocessing Queue.

    Parameters:
    - index: The ID/index of this chunk (used for progress reporting).
    - chunk: List of domain strings to scan.
    - domains: List of DomainDTO objects to compare against.
    - criteria: SniffCriteria object defining the similarity rules.
    - queue: Multiprocessing Queue used to send progress and final results.
    """

    # Set to store SniffResult objects for suspicious matches found in this chunk
    results = set()

    # Calculate how often to report progress; currently using 5% of chunk length
    total_progress = max(len(chunk) * 0.05, 1)

    # Iterate over each domain in the chunk
    for index, domain_to_scan in enumerate(chunk):

        # Compare each domain_to_scan against every reference domain
        for domain in domains:
            sniff_result = compare_domain(domain.name, domain_to_scan, criteria)

            if sniff_result.suspicious:
                results.add(sniff_result)

        # Report progress back to the main process periodically
        # Only send every total_progress steps to avoid overwhelming the queue
        if index > 0 and index % total_progress == 0:
            queue.put(('progress', task_id, total_progress))

    queue.put(('done', task_id, results))


def sniff_file(file: Path, domains: list[DomainDTO], criteria: SniffCriteria, max_workers: int) -> set[SniffResult]:
    """
    Given a file, it will read every domain in it and perform similarity checks
    against one or more reference domains, returning the results.

    Parameters:
    - file: Path object pointing to the file containing domains to scan.
    - domains: List of DomainDTO objects to compare against.
    - criteria: SniffCriteria object specifying the scanning rules.
    - max_workers: Maximum number of parallel worker processes.

    Returns:
    - A set of SniffResult objects representing matches found.
    """

    log.info(f"Sniffing file {file}")

    # Read all lines from the file and strip whitespace
    with open(file, "r") as f:
        domains_to_scan = [line.strip() for line in f.readlines()]

    # Split the list of domains into approximately equal chunks,
    chunks = numpy.array_split(numpy.array(domains_to_scan), max_workers)
  
    # Create a multiprocessing queue for inter-process communication.
    queue = Queue()
    
    # Keep track of all worker processes so we can join them later
    processes: list[Process] = []

    # Store final results from all processes
    results = set()

    with Progress(transient=True, console=console.console) as progress:

        # Dictionary to store progress bars per chunk
        task_bars = {}

        # Launch a worker process for each chunk
        for i, chunk in enumerate(chunks):
            p = Process(
                target=_scan_domains, 
                args=(i, chunk, domains, criteria, queue)
            )
            p.start()
            processes.append(p)  
            task_bars[i] = progress.add_task(f"Chunk {i}", total=len(chunk))

        # Track how many worker processes have finished
        finished = 0
        while finished < max_workers:
            
            msg = queue.get()
            kind, task_id, payload = msg  

            if kind == "progress":
                progress.advance(task_bars[task_id], advance=payload)
            elif kind == "done":
                results.update(payload)
                log.info(f"sniffed chunk {task_id}")
                progress.update(task_bars[task_id], completed=True)
                finished += 1

    log.info(f"sniffed a total of {len(domains_to_scan)} domains")
    
    return results
