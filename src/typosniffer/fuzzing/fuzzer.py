from dnstwist import Fuzzer


POSSIBLE_FORMATS = ['json', 'csv']

def fuzz():
    domain = "internet-idee.net"
    f = Fuzzer(domain)
    f.generate()

    for variant in f.domains:
        yield variant