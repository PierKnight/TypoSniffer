from dnstwist import Fuzzer
from typosniffer.config import config
from typeguard import typechecked
from typosniffer.data.dto import DomainDTO
from typosniffer.utils import utility


POSSIBLE_FORMATS = ['json', 'csv', 'plain']

@typechecked
def fuzz(domain: DomainDTO, tld_dictionary: list[str], word_dictionary: list[str], unicode: bool = False):

    tld_dict = tld_dictionary if tld_dictionary else read_tld_dictionary()

    f = Fuzzer(domain.name, tld_dictionary=tld_dict, dictionary=word_dictionary)
    f.generate()

    for variant in f.domains:
        if unicode:
            variant.domain = variant.domain.encode("ascii").decode("idna")
        yield variant


@typechecked
def read_tld_dictionary() -> list[str]:
    return utility.read_lines(utility.get_resource("tld.txt"))





