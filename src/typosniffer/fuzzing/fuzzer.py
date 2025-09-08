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





