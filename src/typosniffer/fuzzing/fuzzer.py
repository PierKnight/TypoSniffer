from dnstwist import Fuzzer


POSSIBLE_FORMATS = ['json', 'xml']

def fuzz(domain: str):
    f = Fuzzer(domain)
    f.generate()

    for variant in f.domains:
        yield variant