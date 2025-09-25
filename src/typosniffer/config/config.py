
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

class ImageUploadConfig(BaseModel):
	model_config = ConfigDict(frozen=True)
	api_key: str = Field(..., description="Upload Image API Key.")
	expiration: Optional[int] = Field(86400, description="Optional expiration time in seconds.")


# Email configuration for sending notifications
class EmailConfig(BaseModel):
	model_config = ConfigDict(frozen=True)

	smtp_server: str = Field(..., description="SMTP server hostname or IP address.")
	smtp_port: int = Field(..., description="SMTP server port number.")
	smtp_username: str = Field(..., description="Username for SMTP authentication.")
	smtp_password: str = Field(..., description="Password for SMTP authentication.")
	sender_email: EmailStr = Field(..., description="Email address of the sender.")
	receiver_email: EmailStr = Field(..., description="Email address of the recipient.")
	starttls: bool = Field(True, description="Whether to use STARTTLS for secure SMTP connection.")

	imgbb: Optional[ImageUploadConfig] = Field(None, description="Optional ImgBB configuration, it is used to upload temporary page screenshots to be previewed in the email")

	discovery_template: FilePath = Field(default_factory=lambda: get_resource('template/discovery.html.j2'), description="Path to the Jinja2 template used for discovery emails.")
	inspection_template: FilePath = Field(default_factory=lambda: get_resource('template/inspection.html.j2'), description="Path to the Jinja2 template used for inspection emails.")


# Configuration for the discovery step
class DiscoveryConfig(BaseModel):
	model_config = ConfigDict(frozen=True)

	updating_workers: int = Field(default=multiprocessing.cpu_count(), ge=1, description="Thread pool size used to download domain files.")
	discovery_workers: int = Field(default=multiprocessing.cpu_count(), ge=1, description="Process pool size used to scan domain files.")
	days: int = Field(default=1, ge=1, description="Number of days of registered domains to scan.")
	clear_days: Optional[int] = Field(None, ge=1, description="Clear domain files older than this value. If None, defaults to 'days'.")
	criteria: 'SniffCriteria' = Field(default_factory=lambda: SniffCriteria(), description="Criteria used when evaluating a domain.")

	# Whois configuration
	whois_workers: int = Field(default=10, ge=1, description="Thread pool size used to retrieve whois information from domains.")
	requests_per_minute: int = Field(default=10, ge=1, description="Number of whois requests allowed per minute per top-level domain.")


# Configuration for the inspection step
class InspectionConfig(BaseModel):
	model_config = ConfigDict(frozen=True)

	screenshot_dir: DirectoryPath = Field(default_factory=lambda: expand_and_create_dir("~/.typosniffer/screenshots"), description="Directory where website screenshots are saved.")
	page_load_timeout: int = Field(default=30, ge=0, description="Timeout in seconds when loading a page to take a screenshot.")
	hash_threshold: int = Field(default=6, ge=0, le=16, description="Maximum Hamming distance allowed between the latest and current website screenshot hash.")
	max_workers: int = Field(default=multiprocessing.cpu_count(), ge=1, description="Maximum number of workers for parallel inspection tasks.")


# Main application configuration
class AppConfig(BaseModel):
	model_config = ConfigDict(frozen=True, extra='forbid')

	discovery: DiscoveryConfig = Field(default_factory=DiscoveryConfig, description="Configuration for the discovery step.")
	inspection: InspectionConfig = Field(default_factory=InspectionConfig, description="Configuration for the inspection step.")
	email: Optional[EmailConfig] = Field(default=None, description="Email configuration used to send notifications.")


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

		cfg = AppConfig.model_validate(config_data)
	log.info(f"Configuration Loaded")

def get_config() -> AppConfig:
	return cfg

