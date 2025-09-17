from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import whoisit
from whoisit.errors import RateLimitedError
from typosniffer.utils import console
import tldextract
import time

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

def _whoisit(domain: str):
    try:
        return whoisit.domain(domain, allow_insecure_ssl=True, follow_related=False)
    except RateLimitedError as e:
        return whoisit.domain(domain, allow_insecure_ssl=True, follow_related=True)

def find_whois(domains: list[str], requests_per_minute: int, max_workers: int):

    whoisit.bootstrap(overrides=True)

    #domains that need to be processed this list will reduce over time    
    domains_to_process = list(domains)

    results = {}
    
    #keep processing until we got a result for each domain
    while (len(domains_to_process) > 0):

        #collect the first requests_per_minute domains for each tld
        queries, domains_to_process = _collect_whois_domains(domains_to_process, requests_per_minute)
        
        future_to_query = {}

        processed = 0

        #process first 10 queries for each tld
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            
            for domains_per_tdl in queries.values():
                for domain in domains_per_tdl:
                    future_to_query[executor.submit(_whoisit, domain)] = domain

            for future in as_completed(future_to_query):
                try:
                    domain = future_to_query[future]
                    whois_result = future.result()
                    results[domain] = whois_result
                    processed += 1
                except RateLimitedError as e:
                    console.print_error(f"Failed to whois domain: {domain}, {e} retrying in the next batch")
                    domains_to_process.append(domain)
                except Exception as e:
                    console.print_error(f"Failed to whois domain: {domain} retry later, {e}")

        console.print_info(f"Processed {processed}")
        #wait for one minute if there are still domains to be processed
        if len(domains_to_process) > 0:
            with console.status("Waiting for next batch of whoip"):
                time.sleep(60)
        
    return results

        




        
    



