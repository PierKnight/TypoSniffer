from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import cycle
import dns
from dns import exception
from typeguard import typechecked
from typosniffer.fuzzing import fuzzer
from typosniffer.utils.console import console
from dns import resolver
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn




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
def search_dns(domain: str, tld_dictionary: list[str], word_dictionary: list[str], nameservers: list[str], max_workers=30):

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
