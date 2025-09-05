

import json
import re
import xml
import click
from rich_click import RichCommand, RichGroup
from typosniffer.utils.console import console
from typosniffer.config import config
from typosniffer.fuzzing import fuzzer
from typosniffer.utils.utility import validate_regex



def print_banner():
    banner = \
"""
████████╗██╗   ██╗██████╗  ██████╗                   
╚══██╔══╝╚██╗ ██╔╝██╔══██╗██╔═══██╗                  
   ██║    ╚████╔╝ ██████╔╝██║   ██║                  
   ██║     ╚██╔╝  ██╔═══╝ ██║   ██║                  
   ██║      ██║   ██║     ╚██████╔╝                  
   ╚═╝      ╚═╝   ╚═╝      ╚═════╝                   
                                                     
███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗ 
██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║
╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝

By Pierluigi Altimari                                                     

"""
    console.print(banner, style="bold green", highlight=False)


@click.group()
@click.option("-v", "--verbose", is_flag=True)
def cli(verbose):
    print_banner()
    config.load()
    


@cli.command()
@click.option(
    '-f', '--format',
    type=click.Choice(fuzzer.POSSIBLE_FORMATS, case_sensitive=False),
    default=fuzzer.POSSIBLE_FORMATS[0],
    help='format of output file'
)
@click.argument('domain', callback=validate_regex(r'^[\w+\.]+\w+', "not valid domain"))
@click.argument('filename')
def fuzzing(filename: str, format: str, domain: str):
    console.print("[bold green]Fuzzing Domain[/bold green]")
    
    with console.status("[bold green]Running Domain Fuzzing..[/bold green]"):
        with open(filename, "w", encoding="utf-8") as f:
            output = dict()
            for domain in fuzzer.fuzz(domain):
                if domain.fuzzer in output:
                    output[domain.fuzzer].append(domain.domain)
                else:
                    output[domain.fuzzer] = [domain.domain]
            
            if format.lower() == 'json':
                json.dump(output, f, indent=4)

                                    



if __name__ == "__main__":
    cli()