
import json
import os
from typing import Optional
import yaml
from pathlib import Path
from pydantic import BaseModel, ConfigDict, DirectoryPath, Field
from typosniffer.utils import console
from typosniffer.utils.utility import expand_and_create_dir

class EmailConfig(BaseModel):
    model_config = ConfigDict(frozen=True)
    smtp_server: str
    smtp_port: int
    smtp_password: str
    sender_email: str
    receiver_email: str

class MonitorConfig(BaseModel):

    screenshot_dir: DirectoryPath = expand_and_create_dir("~/.typosniffer/screenshots")
    page_load_timeout: int = Field(default = 3, ge=0)


class AppConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    monitor: MonitorConfig = MonitorConfig()
    email: Optional[EmailConfig] = None


def path_representer(dumper, data):
    print(data)
    return dumper.represent_str(str(data))


cfg : AppConfig = None

FOLDER = Path(os.path.expanduser("~/.typosniffer"))

def load():
    global cfg
    os.makedirs(FOLDER, exist_ok=True)

    print("LOL")


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


