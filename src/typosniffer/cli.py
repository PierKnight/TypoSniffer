

import json
import click
from rich_click import RichCommand, RichGroup
from typosniffer.utils.console import console
from typosniffer.config import config
from typosniffer.fuzzing import fuzzer



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
    help='Output format: use typosniffer formats to print all possible formats'
)
@click.argument('filename')
def fuzzing(filename: str, format: str):
    console.print("[bold green]Fuzzing Domain[/bold green]")
    
    with console.status("[bold green]Running Domain Fuzzing..[/bold green]"):
        with open(filename, "w", encoding="utf-8") as f:
            output = dict()
            for domain in fuzzer.fuzz():
                if domain.fuzzer in output:
                    output[domain.fuzzer].append(domain.domain)
                else:
                    output[domain.fuzzer] = [domain.domain]
            
            if format.lower() == 'json':
                json.dump(output, f, indent=4)
                                    


if __name__ == "__main__":
    cli()