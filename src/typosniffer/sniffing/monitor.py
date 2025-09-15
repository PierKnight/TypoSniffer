from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import os
from pathlib import Path
from typing import Tuple

import numpy as np
from typosniffer.config import config
from typosniffer.data.database import DB
from typosniffer.data.dto import DomainDTO
from typosniffer.data.tables import WebsiteRecord
from typosniffer.service import website_record
from typosniffer.utils import console, request
from typosniffer.utils.utility import expand_and_create_dir
import uuid
from PIL import Image
import imagehash
import io


def hex_to_binary_array(hex_str, hash_size = 16):
    """
    Converts a hex string back to a numpy boolean array of given hash_size.
    hash_size: total number of bits (e.g., 64 for 8x8 phash)
    """
    # Convert hex string to integer
    int_val = int(hex_str, 16)
    
    # Convert integer to binary string, padded with leading zeros
    bin_str = bin(int_val)[2:].zfill(hash_size)
    
    # Convert to numpy array of 0/1
    bin_array = np.array([int(b) for b in bin_str], dtype=np.uint8)
    
    # Reshape if needed (optional)
    # e.g., bin_array.reshape((8, 8)) for 8x8 phash
    return bin_array



def save_screenshot(domain: DomainDTO, image: bytes) -> Tuple[datetime, Path]:


    now = datetime.now()

    random_id = uuid.uuid4().int

    timestamp = now.strftime("%Y%m%d_%H%M%S")

    domain_folder = config.cfg.monitor.screenshot_dir / domain.name

    expand_and_create_dir(domain_folder)

    image_file_path = domain_folder / f"{timestamp}.png"

    with open(image_file_path, "wb") as f:
        f.write(image)
    
    return now, image_file_path 


def scan_domain(domain: DomainDTO):
    
    
    image_path = None
    image_hash = None
    try:

        url = request.resolve_url(domain.name)

        browser = request.Browser(url, timeout=config.cfg.monitor.page_load_timeout)

        image_bytes, url = browser.screenshot()
        
        image_file = io.BytesIO(image_bytes)

        image_hash = imagehash.dhash(Image.open(image_file))

        date, image_path = save_screenshot(domain, image_bytes)
    except Exception as e:
        console.print_error("Failed to retrieve {domain.name} webpage")
        raise


    now_website_exists = image_path != None

    with DB.get_session() as session, session.begin():

        try:
            last_record = website_record.get_last_record_of_domain(session, domain)
        
            last_website_exist = last_record.website_exists if last_record else False

            #if a new record should be saved in the db
            #this is true when transitioning from one existing 
            register_record = now_website_exists ^ last_website_exist

            if now_website_exists and last_website_exist:
                register_record = imagehash.ImageHash(hex_to_binary_array(last_record.screenshot_hash)) - image_hash > 5

            if register_record:


                new_record = WebsiteRecord(
                    website_url = url,
                    screenshot_hash = str(image_hash),
                    creation_date = date,
                    suspicious_domain_id = domain.id,
                    website_exists = now_website_exists

                )

                print(new_record)

                session.add(new_record)
        except Exception:
            #if transaction fails delete image to maintain consistency
            if image_path:
                os.remove(image_path)
                if len(os.listdir(image_path.parent)) == 0:
                    os.removedirs(image_path.parent)
            raise
        finally:
            pass
    
    return image_hash


def monitor_domains(domains: list[DomainDTO], max_workers: int = 4):


    with ThreadPoolExecutor(max_workers=max_workers) as executor:
   
        futures = {executor.submit(scan_domain, domain): domain for domain in domains}

        for future in as_completed(futures):
            url = futures[future]
            try:
                result = future.result()
                console.print_info(f"{url} -> {result}")
            except Exception as e:
                console.print_error(f"{url} failed: {e}")


    