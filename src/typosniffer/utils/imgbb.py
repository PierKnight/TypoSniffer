


from datetime import datetime
from pathlib import Path
from typing import Optional

import requests

from typosniffer.config.config import ImageUploadSettings
from typosniffer.data.dto import SuspiciousDomainDTO
from typosniffer.service import website_record
from typosniffer.utils.logger import log



def upload_file(image_path: Path, name: str, config: ImageUploadSettings) -> requests.Response:

    # Open the image file in binary mode
    with open(image_path, "rb") as file:
        params = {"key": config.api_key, 'name': name}
        if config.expiration:
            params['expiration'] = config.expiration

        response = requests.post(
            "https://api.imgbb.com/1/upload",
            params=params,
            files={"image": file}
        )
        response.raise_for_status()

        return response
    

def upload_screenshot(suspicious_domain: SuspiciousDomainDTO, date: datetime, config: ImageUploadSettings) -> Optional[str]:
    try:

        file = website_record.get_screenshot(suspicious_domain, date)

        response: requests.Response = upload_file(file, f"{suspicious_domain.name}-{file.stem}", config)

        return response.json()['data']['image']['url']
    
    except Exception:
        log.error(f"Error Uploading Screenshot: %s", suspicious_domain.name, exc_info=True)

