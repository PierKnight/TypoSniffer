from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import cycle
import dns
from dns import exception
from typeguard import typechecked
from typosniffer.fuzzing import fuzzer
from typeguard import name




def resolve_domain(domain, nameserver):
    """Resolve using a specific DNS server."""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [nameserver]
    resolver.lifetime = 3
    resolver.timeout = 2
    answer = resolver.resolve(domain, "A")
    return [rdata.to_text() for rdata in answer]

@typechecked
def search_dns(domain: str, nameservers: list[str], max_workers=50):

    return
    nameserver_cycle = cycle(nameservers)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {}
        for permutation in fuzzer.fuzz(domain):
            domain = permutation.domain
            future_to_domain[executor.submit(resolve_domain, domain, next(nameserver_cycle))] 
                
            
        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:

                ips = future.result()
                if ips:
                    results[domain] = ips
            except exception.Timeout as e:
                pass
            except exception.DNSException as e:
                pass
                
    return results
