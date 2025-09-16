
import json
import os
from typing import Optional
import yaml
from pathlib import Path
from pydantic import BaseModel, ConfigDict, DirectoryPath, EmailStr, Field
from typosniffer.utils import console
from typosniffer.utils.utility import expand_and_create_dir

class EmailConfig(BaseModel):
    model_config = ConfigDict(frozen=True)
    smtp_server: str
    smtp_port: int
    smtp_username: str
    smtp_password: str
    sender_email: EmailStr
    receiver_email: EmailStr
    starttls: bool

class MonitorConfig(BaseModel):

    screenshot_dir: DirectoryPath = expand_and_create_dir("~/.typosniffer/screenshots")
    page_load_timeout: int = Field(default = 30, ge=0)
    hash_threeshold: int = Field(default = 3, ge=0, le=16)
    max_workers: int = Field(default = 4, ge=1)
    


class AppConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    monitor: MonitorConfig = MonitorConfig()
    email: Optional[EmailConfig] = None


cfg : AppConfig = None

FOLDER = Path(os.path.expanduser("~/.typosniffer"))

def load():
    global cfg
    os.makedirs(FOLDER, exist_ok=True)

    config_file = FOLDER / "config.yaml"
    
    if not config_file.exists():
        default_cfg = AppConfig()
        config_json = default_cfg.model_dump_json()
        
        data = json.loads(config_json)

        with open(config_file, "w") as f:
            yaml.dump(data , f, sort_keys=False)
    
    # Load YAML
    with open(config_file, "r") as f:
        config_data = yaml.safe_load(f)

        cfg = AppConfig(**config_data)
        console.print_info("Loaded App Configuration")

def get_config() -> AppConfig:
    return cfg

