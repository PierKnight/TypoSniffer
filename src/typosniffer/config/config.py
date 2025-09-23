
import json
import os
from typing import Optional
import yaml
from pydantic import BaseModel, ConfigDict, DirectoryPath, EmailStr, Field, FilePath
from typosniffer import FOLDER
from typosniffer.data.dto import SniffCriteria
from typosniffer.utils.utility import expand_and_create_dir, get_resource
from typosniffer.utils.logger import log
import multiprocessing

class EmailConfig(BaseModel):
    model_config = ConfigDict(frozen=True)
    smtp_server: str
    smtp_port: int
    smtp_username: str
    smtp_password: str
    sender_email: EmailStr
    receiver_email: EmailStr
    starttls: bool

    discovery_template: FilePath = get_resource('template/discovery.html.j2')
    inspection_template: FilePath = get_resource('template/inspection.html.j2')


#configuration used in the discovery step
class DiscoveryConfig(BaseModel):
    model_config = ConfigDict(frozen=True)
    updating_workers: int = Field(default = multiprocessing.cpu_count(), ge=1, description='Thread Pool Size used to download domain files')
    discovery_workers: int = Field(default = multiprocessing.cpu_count(), ge=1, description='Process Pool Size used to scan domain files')
    days: int = Field(default = 1, ge=1)
    clear_days: Optional[int] = Field(None, ge=1)
    criteria: SniffCriteria = Field(SniffCriteria(), description='Criteria used when evaluating a domain')
    
    #whois
    whois_workers: int = Field(default = 10, ge=1, description='Thread Pool Size used to retrieve whois information from domains')
    requests_per_minute: int = Field(default = 10, ge=1, description='Whois request per minute per Top-Level Domain')

#configuration used in the inspection step
class MonitorConfig(BaseModel):

    screenshot_dir: DirectoryPath = expand_and_create_dir("~/.typosniffer/screenshots")
    page_load_timeout: int = Field(default = 30, ge=0)
    hash_threeshold: int = Field(default = 6, ge=0, le=16)
    max_workers: int = Field(default = multiprocessing.cpu_count(), ge=1)
    


class AppConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    discovery: DiscoveryConfig = DiscoveryConfig()
    inspection: MonitorConfig = MonitorConfig()
    email: Optional[EmailConfig] = None


cfg : AppConfig = None

CONFIG = FOLDER / "config.yaml"

def load():

    log.info(f"Loading Configuration at {CONFIG}")

    global cfg
    os.makedirs(FOLDER, exist_ok=True)
    
    if not CONFIG.exists():
        log.info("Config not found, creating default confgi")
        default_cfg = AppConfig()
        config_json = default_cfg.model_dump_json()
        
        data = json.loads(config_json)

        with open(CONFIG, "w") as f:
            yaml.dump(data , f, sort_keys=False)
    
    # Load YAML
    with open(CONFIG, "r") as f:
        config_data = yaml.safe_load(f)

        cfg = AppConfig(**config_data)
    log.info(f"Configuration Loaded")

def get_config() -> AppConfig:
    return cfg

