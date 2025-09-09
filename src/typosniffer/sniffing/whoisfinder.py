from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import whois
from typosniffer.utils import utility
from typosniffer.utils.console import console
import tldextract
import time
import random

def _collect_whois_domains(domains, requests_per_minute: int):
        """
            given a list of domains get the first "requests_per_minute" domains for each tld
        """
        queries_per_tld = defaultdict(list)

        remaining_domains = []

        for domain in domains:
            tld = tldextract.extract(domain).suffix
            if len(queries_per_tld[tld]) < requests_per_minute:
                queries_per_tld[tld].append(domain)
            else:
                remaining_domains.append(domain)  # keep domains that couldn't be added

        return dict(queries_per_tld), remaining_domains


def find_whois(domains: list[str], requests_per_minute: int = 10, max_workers: int = 10):
    

    def handle_whos(domain: str):
        return whois.whois(domain)
    
    domains_to_process = list(domains)

    results = {}
    
    while (len(domains_to_process) > 0):

        queries, domains_to_process = _collect_whois_domains(domains_to_process, requests_per_minute)
        
        future_to_query = {}


        #process first 10 queries for each tld
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            
            for domains_per_tdl in queries.values():
                for domain in domains_per_tdl:
                    future_to_query[executor.submit(handle_whos, domain)] = domain

            for future in as_completed(future_to_query):
                try:
                    domain = future_to_query[future]
                    whois = future.result()
                    results[domain] = whois
                except Exception as e:
                    console.print(f"[bold red]Failed to whois domain: {domain} retry later, {e}[/bold red]")
                    domains_to_process.append(domain)

                finally:
                    pass
        
        console.print(f"[bold green]Processed {len(future_to_query)} [/bold green]")
        #wait for one minute
        if len(domains_to_process) > 0:
            console.print(f"[bold green]Waiting for next batch of whoip [/bold green]")
            time.sleep(60)
        
    return results

        




        
    



