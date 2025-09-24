from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
import whois
import whoisit
from whoisit.errors import RateLimitedError, UnsupportedError, ResourceDoesNotExist
from typosniffer.utils import console
from typosniffer.utils.logger import log
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

def _whois(domain: str):
        
    def parse_date(date):

        if isinstance(date, list):
            return parse_date(date[0])
        elif isinstance(date, datetime.datetime):
            return date

        return datetime.datetime.strptime(date, "%Y-%m-%d %H:%M:%S") if date else None
    
    def parse_list(data):
        if isinstance(data, list):
            return data
        if data is None:
            return None
        return [data]
    

    whois_data = whois.whois(domain)

    dnssec_val = whois_data.get("dnssec")
    if dnssec_val is None:
        dnssec = None
    elif dnssec_val == "unsigned":
        dnssec = False
    else:
        dnssec = dnssec_val

    return {
        "nameservers": parse_list(whois_data.get("name_servers")),
        "whois_server": whois_data.get("whois_server"),
        "status": parse_list(whois_data.get("status")),
        "creation_date": parse_date(whois_data.get("creation_date")),
        "updated_date": parse_date(whois_data.get("updated_date")),
        "expiration_date": parse_date(whois_data.get("expiration_date")),
        "dnssec": dnssec,
    }

def get_whois(domain: str):

    log.debug(f"Retrive whois data of {domain} domain")

    try:
        try:
            log.debug(f"use rdap protocol on {domain} with follow related disabled")
            return whoisit.domain(domain, allow_insecure_ssl=True, follow_related=False)
        except RateLimitedError:
            log.debug(f"use rdap protocol on {domain} with follow related enabled")
            return whoisit.domain(domain, allow_insecure_ssl=True, follow_related=True)
    except (UnsupportedError, ResourceDoesNotExist):
        log.debug(f"Fallback to whois domain {domain}")
        return _whois(domain)
        

def find_whois(domains: list[str], requests_per_minute: int, max_workers: int):

    log.info(f"Finding whois/rdap data: request per minute {requests_per_minute} and max workers: {max_workers}")

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
                    future_to_query[executor.submit(get_whois, domain)] = domain

            for future in as_completed(future_to_query):
                try:
                    domain = future_to_query[future]
                    whois_result = future.result()
                    results[domain] = whois_result
                    processed += 1
                except RateLimitedError as e:
                    console.print_error(f"Failed to whois domain: {domain}, {e} retrying in the next batch")
                    domains_to_process.append(domain)
                    log.error("Rate limited whois query", exc_info=True)
                except Exception as e:
                    console.print_error(f"Failed query to whois domain: {domain} retry later, {e}")
                    log.error("Failed query to whois query", exc_info=True)

        
        console.print_info(f"retrieved {processed} whois data")
        #wait for one minute if there are still domains to be processed
        if len(domains_to_process) > 0:
            log.info(f"Waiting 60 seconds for next batch")
            with console.status("Waiting for next batch of whoip"):
                time.sleep(60)
        
        log.info(f"whois complete")
        
    return results

        




        
    



