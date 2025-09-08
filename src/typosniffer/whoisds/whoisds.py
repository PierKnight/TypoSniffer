import base64
from concurrent.futures import ThreadPoolExecutor, as_completed, ProcessPoolExecutor
from datetime import datetime, timedelta
import os
from pathlib import Path
from typosniffer.utils import request
from typosniffer.config import config
from typosniffer.utils.console import console
from typosniffer.sniffing import sniffer
from zipfile import ZipFile
from io import BytesIO
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.table import Table


WHOISDS_FOLDER = config.FOLDER / "whoisds"


def __format_date(date: datetime.date):
    return date.strftime("%Y-%m-%d") 


def get_whoisds_zip(date: datetime.date) -> bool:
    """
        Given a date download the zip file containing the newly registered domains for that date and update file
    """
    date_string = __format_date(date)
    domain_file = Path(WHOISDS_FOLDER / f"{date_string}.txt")

    if domain_file.is_file():
        return False

    base64_date_zip = base64.b64encode(f"{date_string}.zip".encode("utf-8")).decode("utf-8")
    url = f"https://www.whoisds.com//whois-database/newly-registered-domains/{base64_date_zip}/nrd"
    response = request.get(url)

    zip_file = ZipFile(BytesIO(response.content))

    with zip_file.open("domain-names.txt") as src, open(domain_file, "wb") as dst:
         # read in chunks to avoid loading entire file into memory
        for chunk in iter(lambda: src.read(4096), b""):
            dst.write(chunk)

    return True

def __get_domains_file():
    for filename in os.listdir(WHOISDS_FOLDER):
        try:
            # Extract date from filename
            file_date_str = filename.replace(".txt", "")
            file_date = datetime.strptime(file_date_str, "%Y-%m-%d")
            file_path = os.path.join(WHOISDS_FOLDER, filename)
            yield file_date, file_path
        except ValueError:
            pass
        
        
def clean_old_domains(max_days: int = 30) -> int:
    """
    Delete whoisds domain files that are older than max_days.
    
    Args:
        max_days (int): Age in days; files older than this are removed. Defaults to 30.
    
    Returns:
        int: Number of files deleted.
    """
    today = datetime.today()
    total_cleaned = 0
    for filename in os.listdir(WHOISDS_FOLDER):
        try:
            # Extract date from filename
            file_date_str = filename.replace(".txt", "")
            file_date = datetime.strptime(file_date_str, "%Y-%m-%d")
            
            # Check if file is one month or older
            if today - file_date >= timedelta(days=max_days):
                file_path = os.path.join(WHOISDS_FOLDER, filename)
                os.remove(file_path)
                total_cleaned += 1
        except ValueError:
            pass
    return total_cleaned


def __update_domains(update_days : int = 10, max_workers: int = 10):
    total_updated = 0
    today = datetime.today()
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_date = {}

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task("[green]Updating domains file...", total=update_days)
            for i in range(0, update_days):
                date = today - timedelta(days=i+1)
                future_to_date[executor.submit(get_whoisds_zip, date)] = __format_date(date)
                
            for future in as_completed(future_to_date):
                date = future_to_date[future]
                try:
                    updated = future.result()
                    if updated:
                        total_updated += 1
                except Exception as e:
                    console.print(f"[bold red]Failed to retrieve domain file: {date}, {e}[/bold red]") 
                finally:
                    progress.update(task, advance=1)
    console.print(f"[bold green]{total_updated} Domain File have been updated[/bold green]")


def sniff_whoisds(domain: str, criteria: sniffer.SniffCriteria, max_workers: int = 10) -> set[sniffer.SniffResult]:


    results = set()

    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        future_to_file = {}

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("[green]{task.completed}/{task.total} domain file scanned"),
            console=console
        ) as progress:
            
            total_files = 0

            for date, file in __get_domains_file():
                future_to_file[executor.submit(sniffer.sniff_file, file, domain, criteria)] = file
                total_files += 1
            
            console.print(f"[bold green]Found {total_files} domain file/s![/bold green]")

            task = progress.add_task("[green]Sniffing Domain Files...", total=total_files)
            
            for future in as_completed(future_to_file):
                date = future_to_file[future]
                try:
                    results.update(future.result())
                except Exception as e:
                    console.print(f"[bold red]Failed to sniff domain file: {date}, {file}[/bold red]") 
                finally:
                    progress.update(task, advance=1)

    console.print("[bold green]Domain Sniffing completed![/bold green]")
    table = Table(title="Suspicious Domains")
    table.add_column("Domain", style="bold red")
    domains = [r.domain for r in results]
    for domain in domains:
        table.add_row(domain)

    console.print(table)

    return results
    
    


def whoisds_cli(domain: str, criteria: sniffer.SniffCriteria, update_days : int = 10, max_days: int = -1, max_workers: int = 10):

    #make sure whoisds_folder exists
    
    os.makedirs(WHOISDS_FOLDER, exist_ok=True)

    #clear if max_days is set
    if max_days > 0:
        with console.status("[bold green]Cleaning old Domains[/bold green]"):
            clean_old_domains(max)

    __update_domains(update_days, max_workers)
    
    return sniff_whoisds(domain, criteria)

    
