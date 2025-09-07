from pathlib import Path
from dnstwist import Fuzzer
from typosniffer.config import config
from typeguard import typechecked
import requests
from typing import Optional
from typosniffer.utils import utility
from typosniffer.utils.console import console


POSSIBLE_FORMATS = ['json', 'csv', 'plain']
TLD_FILE = config.FOLDER / "tdls.txt"
IANA_TLD = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"

DICTIONARY = ('auth', 'account', 'confirm', 'connect', 'enroll', 'http', 'https', 'info', 'login', 'mail', 'my',
	'online', 'payment', 'portal', 'recovery', 'register', 'ssl', 'safe', 'secure', 'signin', 'signup', 'support',
	'update', 'user', 'verify', 'verification', 'web', 'www')
TLD_DICTIONARY = ('com', 'net', 'org', 'info', 'cn', 'co', 'eu', 'de', 'uk', 'pw', 'ga', 'gq', 'tk', 'ml', 'cf',
	'app', 'biz', 'top', 'xyz', 'online', 'site', 'live')


@typechecked
def fuzz(domain: str, tld_dictionary: list[str], word_dictionary: list[str]):

    tld_dict = tld_dictionary if tld_dictionary else read_tld_dictionary()

    f = Fuzzer(domain, tld_dictionary=tld_dict, dictionary=word_dictionary)
    f.generate()

    for variant in f.domains:
        yield variant


@typechecked
def read_tld_dictionary() -> list[str]:
    return utility.read_lines(utility.get_dictionary("tld.txt"))



def update_tld_dictionary():
    try:
        response = requests.get(IANA_TLD)
        response.raise_for_status()

        with open(TLD_FILE, "w", encoding="utf-8") as f:
            f.write(response.text)
        
        console.print(f"[green]Updated tld successfully to[/green] [bold]{TLD_FILE}[/bold]")
    except requests.exceptions.RequestException as e:
        console.print(f"[red]Network error:[/red] {e}")
    except OSError as e:
        console.print(f"[red]File error:[/red] {e}")
    except Exception as e:
        console.print(f"[red]Unexpected error:[/red] {e}")
    
    




