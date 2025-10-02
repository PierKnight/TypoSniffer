import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
import os
from pathlib import Path
import typosniffer
from typosniffer.data.dto import DomainDTO
from typosniffer.utils import request
from typosniffer.utils.logger import log
from typosniffer.utils.console import console
from typosniffer.sniffing import sniffer
from zipfile import ZipFile
from io import BytesIO
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.table import Table


WHOISDS_FOLDER = typosniffer.FOLDER / "whoisds"

class WhoIsDsFile:

    path: Path
    date: str

    def __init__(self, date: datetime):
        date_string = date.strftime("%Y-%m-%d") 
        self.date = date_string
        self.path = Path(WHOISDS_FOLDER / f"{date_string}.txt")


def _get_whoisds_zip(file: WhoIsDsFile) -> bool:
    """
        Given a date download the zip file containing the newly registered domains for that date and update file
    """

    date_string = file.date

    log.info(f"retrieving whoisds domain file {file.path}")

    if file.path.is_file():
        log.info(f"file already present skipping")
        return False
    

    base64_date_zip = base64.b64encode(f"{date_string}.zip".encode("utf-8")).decode("utf-8")
    url = f"https://www.whoisds.com//whois-database/newly-registered-domains/{base64_date_zip}/nrd"

    log.info(f"Downloading domain file {url}")

    response = request.get(url)

    zip_file = ZipFile(BytesIO(response.content))

    with zip_file.open("domain-names.txt") as src, open(file.path, "wb") as dst:
         # read in chunks to avoid loading entire file into memory
        for chunk in iter(lambda: src.read(4096), b""):
            dst.write(chunk)

    log.info(f"Downloaded domain file {url}")

    return True
        
def clear_old_domains(max_days: int = 30) -> int:
    """
    Delete whoisds domain files that are older than max_days.
    
    Args:
        max_days (int): Age in days; files older than this are removed. Defaults to 30.
    
    Returns:
        int: Number of files deleted.
    """

    log.info(f"Start cleaning old whoisds files: {max_days} max days")

    os.makedirs(WHOISDS_FOLDER, exist_ok=True)

    today = datetime.today()
    total_cleaned = 0
    for filename in os.listdir(WHOISDS_FOLDER):
        try:
            # Extract date from filename
            file_date_str = filename.replace(".txt", "")
            file_date = datetime.strptime(file_date_str, "%Y-%m-%d")
            
            # Check if file is one month or older
            if today - file_date > timedelta(days=max_days):
                file_path = os.path.join(WHOISDS_FOLDER, filename)
                os.remove(file_path)
                total_cleaned += 1
        except ValueError:
            pass

    log.info(f"Removed {total_cleaned} files")
    
    return total_cleaned


def update_domains(update_days : int = 10, max_workers: int = 10) -> list[WhoIsDsFile]:
    """
        Scans stored whoisds domain files and updates them if missing in a specific day in the range (today - 1, totay - 1 - update_days)
        returns the list of updated file dates.
    """
    os.makedirs(WHOISDS_FOLDER, exist_ok=True)

    log.info(f"updating last {update_days} days using {max_workers} workers")

    total_updated = []
    today = datetime.today()
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_file = {}

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
                file = WhoIsDsFile(date)
                future_to_file[executor.submit(_get_whoisds_zip, file)] = file

                log.debug(f"Updating whoisds file date {file.date}")
                
            for future in as_completed(future_to_file):
                file: WhoIsDsFile = future_to_file[future]
                try:
                    updated = future.result()
                    if updated:
                        total_updated.append(file)
                except Exception as e:
                    log.error(f"Failed to retrieve file {file.path}", exc_info=True)
                    console.print(f"[bold red]Failed to retrieve domain file: {date}, {e}[/bold red]") 
                finally:
                    progress.update(task, advance=1)
    
    log.info(f"Updated {len(total_updated)} files")
    console.print(f"[bold green]{len(total_updated)} Domain File have been updated[/bold green]")

    return total_updated


def sniff_whoisds(domains: list[DomainDTO], whoisds_files: list[WhoIsDsFile], criteria: typosniffer.data.dto.SniffCriteria, max_workers: int) -> set[sniffer.SniffResult]:

    os.makedirs(WHOISDS_FOLDER, exist_ok=True)

    results = set()

    log.info(f"Sniffing domain files with criteria {criteria}")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("[green]{task.completed}/{task.total} domain file scanned"),
        console=console
    ) as progress:
        
        total_files = len(whoisds_files)

        task = progress.add_task("[green]Sniffing Domain Files...", total=total_files)

        for file in whoisds_files:
            sniff_results = sniffer.sniff_file(file.path, domains, criteria, max_workers)
            results.update(sniff_results)
            progress.update(task, advance=1)
        
        console.print(f"[bold green]Found {total_files} domain file/s![/bold green]")

    log.info(f"domain sniffing complete")
    console.print("[bold green]Domain Sniffing completed![/bold green]")

    if len(results) > 0:
        table = Table(title="Suspicious Domains")
        table.add_column("Domain", style="bold red")
        sniff_domains = [r.domain for r in results]
        for domain in sniff_domains:
            table.add_row(domain)
        console.print(table)
    else:
        console.print("[bold green]Nothing new to see here[/bold green]")

    return results
    

    
