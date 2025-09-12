from pathlib import Path
import click
from typosniffer.data.dto import DomainDTO
from typosniffer.fuzzing import fuzzer
from typosniffer.utils import utility
from typosniffer.utils import console


@click.command()
@click.option(
    '-tld', '--tld-dictionary',
    type=click.Path(exists=True),
    help='Top Level Domain list',
    callback=utility.list_file_option,
    default=utility.get_resource("tld.txt")
)
@click.option(
    '-wd', '--word-dictionary',
    type=click.Path(exists=True),
    help='Word Dictionary to use',
    callback=utility.list_file_option,
    default=utility.get_resource("words.txt")
)
@click.option('-f', '--format', type=click.Choice(fuzzer.POSSIBLE_FORMATS, case_sensitive=False), default=fuzzer.POSSIBLE_FORMATS[2], help='format of output file')
@click.option('-u', '--unicode', is_flag=True, default=False, help='Write domains in unicode instead of punycode')
@click.argument('domain')
@click.argument('filename', type=click.Path(dir_okay=True, writable=True))
def fuzzing(unicode: bool, tld_dictionary: list[str], word_dictionary: list[str], filename: str, format: str, domain: str):
    """Generate possible permutations of a given domain used in typosquatting"""
    format = format.lower()

    domain_dto = DomainDTO(name=domain)

    with console.status("[bold green]Running Domain Fuzzing..[/bold green]"):
        file_path = Path(filename).resolve()

        fuzz_generator = fuzzer.fuzz(domain_dto, tld_dictionary, word_dictionary, unicode)

        if format == 'json':

            output = {}
            for permutation in fuzz_generator:
                output.setdefault(permutation.fuzzer, []).append(permutation.domain)

            utility.save_as_json(output, file_path)
        elif format == 'csv':
            utility.save_as_csv(fuzz_generator, file_path)
        else:
            console.print_error(f"Unknown format: {output}. Supported: json, plain, csv")
            return