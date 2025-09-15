



from concurrent.futures import ProcessPoolExecutor, as_completed
import datetime
from typosniffer.config import config
from typosniffer.data.dto import DomainDTO
from typosniffer.utils import console, request
from typosniffer.utils.utility import expand_and_create_dir
import uuid
from PIL import Image
import imagehash
import io






def save_screenshot(domain: DomainDTO, image: bytes) -> str:


    random_id = uuid.uuid4().int

    now = datetime.datetime.now()
    timestamp = now.strftime("%Y%m%d_%H%M%S")

    domain_folder = config.cfg.monitor.screenshot_dir / domain.name

    expand_and_create_dir(domain_folder)

    with open(domain_folder / f"{timestamp}.png", "wb") as f:
        f.write(image)
    
    return timestamp


def scan_domain(domain: DomainDTO):
    
    url = request.resolve_url(domain.name)
  
    image_bytes = request.website_screenshot(url, timeout=config.cfg.monitor.page_load_timeout)
    

    image_file = io.BytesIO(image_bytes)

    image_hash = imagehash.dhash(Image.open(image_file))

    timestamp = save_screenshot(domain, image_bytes)
    


    return image_hash


def monitor_domains(domains: list[DomainDTO], max_workers: int = 4):


    with ProcessPoolExecutor(max_workers=max_workers) as executor:
   
        futures = {executor.submit(scan_domain, domain): domain for domain in domains}

        for future in as_completed(futures):
            url = futures[future]
            try:
                result = future.result()
                console.print_info(f"{url} -> {result}")
            except Exception as e:
                console.print_error(f"{url} failed: {e}")


    