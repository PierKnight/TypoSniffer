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
from typosniffer.data.dto import WebsiteStatus
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
    status : WebsiteStatus

@dataclass(frozen=True)
class PhishingReport:
    cnn_similarity: float
    hash_similarity: float

@dataclass(frozen=True)
class DomainReport:
    suspicious_domain: SuspiciousDomainDTO
    update_report: Optional[UpdateReport] = None
    phishing_report: Optional[PhishingReport] = None
    error_msg: Optional[str] = None



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


def compare_records(last_record: Optional[WebsiteRecord], new_record: WebsiteRecord) -> Optional[WebsiteStatus]:
    """
    Compares the previous website record with the new one to determine the website's current status.

    Args:
        last_record (Optional[WebsiteRecord]): The last recorded state of the website.
        new_record (WebsiteRecord): The latest recorded state of the website.

    Returns:
        Optional[WebsiteStatus]: The updated status of the website, which can be:
            - WebsiteStatus.UP
            - WebsiteStatus.DOWN
            - WebsiteStatus.CHANGED
            - None if no change is detected
    """

    # Load monitoring configuration (e.g., hash threshold for detecting changes)
    cfg = get_config().monitor
    
    # Check if the new website record exists
    new_website_exist = new_record is not None
    
    # Check if the last recorded website was considered "up"
    # If there is no last record, assume it was not up
    last_website_exist = last_record.status.is_website_up() if last_record else False

    status = None  # Default status if no change is detected

    if new_website_exist:

        if last_website_exist:
            # Both last and new records exist; compare screenshots to detect changes
            difference = imagehash.hex_to_hash(last_record.screenshot_hash) - imagehash.hex_to_hash(new_record.screenshot_hash)

            print(f"PHISH HASH SIZE {len(imagehash.hex_to_hash(last_record.screenshot_hash))}")
            print(f"COMPARE HASH DIFF {difference}")
            
            # If the image difference exceeds the configured threshold, mark as changed
            if difference > cfg.hash_threeshold:
                status = WebsiteStatus.CHANGED  
        else:
            # New website exists, but last one was down; mark as UP
            status = WebsiteStatus.UP  
            
    elif last_website_exist:
        # New website record does not exist, but last one was up; mark as DOWN
        status = WebsiteStatus.DOWN  

    # Return the computed status
    return status


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
            suspicious_domain_id = domain.id
        )
        
        new_status = compare_records(last_record, new_record)
        if new_status:
            new_record.status = new_status
            session.add(new_record)
            if now_website_exists:
                save_screenshot(date, domain, screenshot)
            return UpdateReport(date=date, url=new_record.website_url, status=new_status)

    return None



def check_domain_phishing(real_screenshot: Optional[ScreenShotInfo], phish_screenshot: Optional[ScreenShotInfo], image_comparator: cnn.ImageComparator) -> PhishingReport:
    
    if real_screenshot and phish_screenshot:
    
        #method that compares sus domain to real domain screenshot 
        real_hash = imagehash.phash(real_screenshot.image)
        phish_hash = imagehash.phash(phish_screenshot.image)

        print(f"PHISH HASH SIZE {len(real_hash)}")
        print(f"PHISH HASH DIFF {real_hash - phish_hash}")

        hash_similarity = (real_hash - phish_hash) / 64
        cnn_similarity = image_comparator.get_similarity(real_screenshot.image, phish_screenshot.image)

        return PhishingReport(cnn_similarity, hash_similarity)
    return None


def scan_domain(domain: SuspiciousDomainDTO, screenshot_data: DomainScreenshotBucket, image_comparator: cnn.ImageComparator) -> DomainReport:
    
    phish_screenshot = get_screenshot(domain.name)

    update_report = check_domain_updated(phish_screenshot, domain)
    return DomainReport(
        suspicious_domain = domain,
        update_report = update_report,
        phishing_report = check_domain_phishing(screenshot_data.get(domain.original_domain), phish_screenshot, image_comparator) if update_report else None
    )


def inspect_domains(domains: list[SuspiciousDomainDTO], max_workers: int = 4) -> list[DomainReport]:


    image_comparator = cnn.ImageComparator()

    original_domains = set([domain.original_domain for domain in domains])

    screenshot_data = DomainScreenshotBucket(len(original_domains))

    reports = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
   
        futures = {executor.submit(scan_domain, domain, screenshot_data, image_comparator): domain for domain in domains}

        for future in as_completed(futures):
            domain = futures[future]
            try:
                report = future.result()
                if report.update_report:
                    reports.append(report)
            except WebDriverException:
                console.print_error(error_msg=f"Failed to retrieve: {domain}")
            except TimeoutException:
                console.print_error(suspicious_domain=domain, error_msg=f"Website took too much time to load: {domain}")
            except Exception:
                console.print_error(suspicious_domain=domain, error_msg=f"Failed to inspect domain, generic error: {domain}")
                console.console.print_exception()
                
    return reports


    