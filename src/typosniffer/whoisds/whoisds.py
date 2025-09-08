import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
import os
from pathlib import Path
from typosniffer.utils import request
from typosniffer.config import config
from typosniffer.utils.console import console
from zipfile import ZipFile
from io import BytesIO
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn


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
        
def clean_old_domains(max_days: int = 30):
    today = datetime.today()
    for filename in os.listdir(WHOISDS_FOLDER):
        try:
            # Extract date from filename
            file_date_str = filename.replace(".txt", "")
            file_date = datetime.strptime(file_date_str, "%Y-%m-%d")
            
            # Check if file is one month or older
            if today - file_date >= timedelta(days=max_days):
                file_path = os.path.join(WHOISDS_FOLDER, filename)
                os.remove(file_path)
        except ValueError:
            pass


def whoisds_cli(days_back : int = 10, max_workers: int = 10):

    #make sure whoisds_folder exists
    
    os.makedirs(WHOISDS_FOLDER, exist_ok=True)

    with console.status("[bold green]Cleaning old Domains[/bold green]"):
        clean_old_domains()

        
    total_updated = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_date = {}

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task("[green]Updating domains file...", total=days_back)
            for i in range(0, days_back):
                date = datetime.today() - timedelta(days=i+1)
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