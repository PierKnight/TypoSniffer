from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import os
from pathlib import Path
from typing import Optional

from dataclasses import dataclass
from typosniffer.config.config import get_config
from typosniffer.data.database import DB
from typosniffer.data.dto import SuspiciousDomainDTO
from typosniffer.data.tables import WebsiteRecord
from typosniffer.service import website_record
from typosniffer.utils import console, request
from typosniffer.utils.utility import expand_and_create_dir
import uuid
from PIL import Image
import imagehash
import io


@dataclass(frozen=True)
class ScreenShotInfo:
    image: bytes
    hash: imagehash.ImageHash
    url: str

def get_screenshot(domain: SuspiciousDomainDTO) -> ScreenShotInfo:

    try:

        url = request.resolve_url(domain.name)

        browser = request.Browser(url, timeout=get_config().monitor.page_load_timeout)

        image_bytes, url = browser.screenshot()
        
        image_file = io.BytesIO(image_bytes)

        image_hash = imagehash.dhash(Image.open(image_file))

        return ScreenShotInfo(image_bytes, image_hash, url)

    except Exception as e:
        console.print_error(f"Failed to retrieve {url} webpage")
        raise

def save_screenshot(date: datetime, domain: SuspiciousDomainDTO, image: bytes) -> Path:



    random_id = uuid.uuid4().int

    timestamp = date.strftime("%Y%m%d_%H%M%S")

    domain_folder = get_config().monitor.screenshot_dir / domain.name

    expand_and_create_dir(domain_folder)

    image_file_path = domain_folder / f"{timestamp}.png"

    with open(image_file_path, "wb") as f:
        f.write(image)
    
    return image_file_path 


def compare_records(last_record: Optional[WebsiteRecord], new_record: WebsiteRecord) -> bool:
    """Returns true if the two records are different and needs to be saved"""


    cfg = get_config().monitor

    last_website_exist = last_record.website_exists if last_record else False

    register_record = last_website_exist ^ new_record.website_exists

    if last_record.website_exists and new_record.website_exists:
            difference = imagehash.hex_to_hash(last_record.screenshot_hash) - imagehash.hex_to_hash(new_record.screenshot_hash)
            
            print(f"DIFFERENCE {difference}")
            if difference > cfg.hash_threeshold:
                register_record = True
    
    return register_record

def scan_domain(domain: SuspiciousDomainDTO):
    
    print("START SCAN")
    
    screenshot = get_screenshot(domain)

    now_website_exists = screenshot.hash is not None
    image_path = None

    with DB.get_session() as session, session.begin():

        try:
            last_record = website_record.get_last_record_of_domain(session, domain)
        
            date = datetime.now()

            new_record = WebsiteRecord(
                website_url = screenshot.url,
                screenshot_hash = str(screenshot.hash),
                creation_date = date,
                suspicious_domain_id = domain.id,
                website_exists = now_website_exists
            )
            
            if compare_records(last_record, new_record):
                session.add(new_record)
                image_path = save_screenshot(date, domain, screenshot.image)

        except Exception:
            #if transaction fails delete image to maintain consistency
            if image_path:
                os.remove(image_path)
                if len(os.listdir(image_path.parent)) == 0:
                    os.removedirs(image_path.parent)
            raise
    
    return screenshot


def monitor_domains(domains: list[SuspiciousDomainDTO], max_workers: int = 4):


    with ThreadPoolExecutor(max_workers=max_workers) as executor:
   
        futures = {executor.submit(scan_domain, domain): domain for domain in domains}

        for future in as_completed(futures):
            domain = futures[future]
            try:
                result = future.result()
                console.print_info(f"{result.url} -> {result.hash}")
            except Exception:
                console.console.print(f"{domain} failed")
                console.console.print_exception()


    