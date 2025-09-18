from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
import threading
from typing import Optional
from selenium.common.exceptions import WebDriverException, TimeoutException
from dataclasses import dataclass
from typosniffer.config.config import get_config
from typosniffer.data.database import DB
from typosniffer.data.dto import SuspiciousDomainDTO
from typosniffer.data.tables import WebsiteRecord
from typosniffer.service import website_record
from typosniffer.sniffing import cnn
from typosniffer.utils import console, request
from typosniffer.utils.utility import expand_and_create_dir
from PIL import Image
import imagehash
import io



@dataclass(frozen=True)
class ScreenShotInfo:
    image: Image.Image
    url: Optional[str]

@dataclass(frozen=True)
class UpdateReport:
    url: str
    date: datetime

@dataclass(frozen=True)
class PhishingReport:
    cnn_similarity: float
    hash_similarity: float

@dataclass(frozen=True)
class DomainReport:
    suspicious_domain: SuspiciousDomainDTO
    update_report: Optional[UpdateReport]
    phishing_report: Optional[PhishingReport]



class DomainScreenshotBucket:
    """This is used to cache domains screenshots in a thread safe manner"""

    def __init__(self, total_domains):
        self.images = {}
        self.num_buckets = total_domains
        self.locks = [threading.Lock() for _ in range(total_domains)]

    def _get_lock(self, key):
        return self.locks[hash(key) % self.num_buckets]

    def get(self, domain: str):
        lock = self._get_lock(domain)
        with lock:
            image = self.images.get(domain, None)
            if not image:
                image = get_screenshot(domain)
                self.images[domain] = image
            return image 



        
        
def get_screenshot_from_file(domain: SuspiciousDomainDTO, date: datetime) -> Image.Image:

    timestamp = date.strftime("%Y%m%d_%H%M%S")
    image_file = get_config().monitor.screenshot_dir / domain.name / f"{timestamp}.png"
    return Image.open(image_file)
    

def get_screenshot(domain: str) -> Optional[ScreenShotInfo]:


    try:
        url = request.resolve_url(domain)

        browser = request.Browser(url, timeout=get_config().monitor.page_load_timeout)

        image_bytes, url = browser.screenshot()
        
        image_file = io.BytesIO(image_bytes)

        return ScreenShotInfo(Image.open(image_file, formats=['png']), url)
    except WebDriverException as e:
        pass

    return None
    


def save_screenshot(date: datetime, domain: SuspiciousDomainDTO, screenshot: ScreenShotInfo) -> Path:

    timestamp = date.strftime("%Y%m%d_%H%M%S")

    domain_folder = get_config().monitor.screenshot_dir / domain.name

    expand_and_create_dir(domain_folder)

    image_file_path = domain_folder / f"{timestamp}.png"

    screenshot.image.save(image_file_path, 'png')
    
    return image_file_path 


def compare_records(last_record: Optional[WebsiteRecord], new_record: WebsiteRecord) -> bool:
    """Returns true if the two records are different and needs to be saved"""

    cfg = get_config().monitor

    last_website_exist = last_record.website_exists if last_record else False

    register_record = last_record is None or last_website_exist ^ new_record.website_exists

    if last_website_exist and new_record.website_exists:
            difference = imagehash.hex_to_hash(last_record.screenshot_hash) - imagehash.hex_to_hash(new_record.screenshot_hash)
            
            if difference > cfg.hash_threeshold:
                register_record = True
    
    return register_record

def check_domain_updated(screenshot: Optional[ScreenShotInfo], domain: SuspiciousDomainDTO) -> Optional[UpdateReport]:
    

    now_website_exists = screenshot is not None
    screenshot_hash = imagehash.dhash(screenshot.image) if now_website_exists else None 

    with DB.get_session() as session, session.begin():

        last_record = website_record.get_last_record_of_domain(session, domain)
    
        date = datetime.now()

        new_record = WebsiteRecord(
            website_url = screenshot.url if now_website_exists else None,
            screenshot_hash = str(screenshot_hash) if now_website_exists else None,
            creation_date = date,
            suspicious_domain_id = domain.id,
            website_exists = now_website_exists
        )
        
        if compare_records(last_record, new_record):
            session.add(new_record)
            if now_website_exists:
                save_screenshot(date, domain, screenshot)
            return UpdateReport(date=date, url=new_record.website_url)

    return None



def check_domain_phishing(real_screenshot: Optional[ScreenShotInfo], phish_screenshot: Optional[ScreenShotInfo], image_comparator: cnn.ImageComparator) -> PhishingReport:
    
    if real_screenshot and phish_screenshot:
    
        #method that compares sus domain to real domain screenshot 
        real_hash = imagehash.phash(real_screenshot.image)
        phish_hash = imagehash.phash(phish_screenshot.image)

        hash_similarity = (real_hash - phish_hash) / 64
        cnn_similarity = image_comparator.get_similarity(real_screenshot.image, phish_screenshot.image)

        return PhishingReport(cnn_similarity, hash_similarity)
    return None


def scan_domain(domain: SuspiciousDomainDTO, screenshot_data: DomainScreenshotBucket, image_comparator: cnn.ImageComparator) -> DomainReport:
    
    real_domain_screenshot = screenshot_data.get(domain.original_domain)
    phish_screenshot = get_screenshot(domain.name)

    update_report = check_domain_updated(phish_screenshot, domain)
    phishing_report = check_domain_phishing(real_domain_screenshot, phish_screenshot, image_comparator)
    return DomainReport(
        suspicious_domain = domain,
        update_report = update_report,
        phishing_report = phishing_report
    )


def inspect_domains(domains: list[SuspiciousDomainDTO], max_workers: int = 4) -> list[DomainReport]:


    image_comparator = cnn.ImageComparator()

    original_domains = set([domain.original_domain for domain in domains])

    screenshot_data = DomainScreenshotBucket(len(original_domains))

    reports 

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
   
        futures = {executor.submit(scan_domain, domain, screenshot_data, image_comparator): domain for domain in domains}

        for future in as_completed(futures):
            domain = futures[future]
            try:
                report = future.result()
                
                if report.update_report:
                    console.print_info(f"Domain {domain.name} updated: {report.update_report}")
                if report.phishing_report:
                    console.print_info(f"Domain {domain.name} phishing scan: {report.phishing_report}")

            except WebDriverException as e:
                console.print_error(f"Failed to retrieve: {domain}")
            except TimeoutException as e:
                console.print_error(f"Website took too much time to load: {domain}")
            except Exception as e:
                console.print_error(f"Monitor for {domain} failed")
                console.console.print_exception()



    