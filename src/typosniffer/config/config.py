
import os
import pathlib
from typing import ClassVar, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
import yaml
from pydantic import ConfigDict, DirectoryPath, EmailStr, Field, FilePath
from typosniffer import FOLDER
from typosniffer.data.dto import SniffCriteria
from typosniffer.utils.utility import expand_and_create_dir, get_resource
from typosniffer.utils.logger import log
import multiprocessing
from pydantic_settings.sources import PydanticBaseSettingsSource



class AppSettings(BaseSettings):
	"""
	Main application configuration,
	
	The same structure you see here is replicated in the config.yml file, so everything shown here can be configured there.

	Environment variables can also be used, and they take priority over config.yml. For example, APP__DATABASE__USERNAME is a valid variable
	"""
	model_config = SettingsConfigDict(frozen=True, extra='forbid', env_nested_delimiter='__', env_prefix='APP__', env_file='.env', env_file_encoding='utf-8')

	database: "DatabaseSettings" = Field(default_factory=lambda: DatabaseSettings(), description="Configuration for the database connection.")
	discovery: "DiscoverySettings" = Field(default_factory=lambda: DiscoverySettings(), description="Configuration for the discovery step.")
	inspection: "InspectionConfig" = Field(default_factory=lambda: InspectionConfig(), description="Configuration for the inspection step.")
	email: Optional["EmailConfig"] = Field(default=None, description="Email configuration used to send notifications.")

	#custom sources order to prioritize environment settings
	@classmethod
	def settings_customise_sources(
		cls,
		settings_cls: type[BaseSettings],
		init_settings: PydanticBaseSettingsSource,
		env_settings: PydanticBaseSettingsSource,
		dotenv_settings: PydanticBaseSettingsSource,
		file_secret_settings: PydanticBaseSettingsSource,
	) -> tuple[PydanticBaseSettingsSource, ...]:
		return env_settings, dotenv_settings, file_secret_settings, init_settings

class DatabaseSettings(BaseSettings):
	"""Configuration for the database connection."""
	model_config = ConfigDict(frozen=True)

	drivername: str = Field("postgresql+psycopg2", description="The SQLAlchemy database drivername used to connect.")
	username: str = Field("postgres", description="Username for connecting to the database.")
	password: str = Field("postgres", description="Password for authenticating the database user.")
	host: str = Field("localhost", description="Hostname or IP address of the database server.")
	port: int = Field(5432, description="Port number used to connect to the database.")
	database: str = Field("postgres", description="Name of the database to connect to.")

# Configuration for the discovery step
class DiscoverySettings(BaseSettings):
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
class InspectionConfig(BaseSettings):
	model_config = ConfigDict(frozen=True)

	screenshot_dir: DirectoryPath = Field(expand_and_create_dir("~/.typosniffer/screenshots"), description="Directory where website screenshots are saved.")
	page_load_timeout: int = Field(default=30, ge=0, description="Timeout in seconds when loading a page to take a screenshot.")
	hash_threshold: int = Field(default=6, ge=0, le=16, description="Hamming distance between the latest and current website screenshot hashes used to detect changes in the website")
	max_workers: int = Field(default=multiprocessing.cpu_count(), ge=1, description="Maximum number of workers for parallel inspection tasks.")

# Email configuration for sending notifications
class EmailConfig(BaseSettings):
	model_config = ConfigDict(frozen=True)

	smtp_server: str = Field(..., description="SMTP server hostname or IP address.")
	smtp_port: int = Field(..., description="SMTP server port number.")
	smtp_username: str = Field(..., description="Username for SMTP authentication.")
	smtp_password: str = Field(..., description="Password for SMTP authentication.")
	sender_email: EmailStr = Field(..., description="Email address of the sender.")
	receiver_email: EmailStr = Field(..., description="Email address of the recipient.")
	starttls: bool = Field(True, description="Whether to use STARTTLS for secure SMTP connection.")

	imgbb: Optional["ImageUploadConfig"] = Field(None, description="Optional ImgBB configuration, it is used to upload temporary page screenshots to be previewed in the email")
	imgur: Optional["ImageUploadConfig"] = Field(None, description="Optional Imgur configuration, it is used to upload page screenshots to be previewed in the email, expiration parameter is ignored")
	

	discovery_template: FilePath = Field(default_factory=lambda: get_resource('template/discovery.html.j2'), description="Path to the Jinja2 template used for discovery emails.")
	inspection_template: FilePath = Field(default_factory=lambda: get_resource('template/inspection.html.j2'), description="Path to the Jinja2 template used for inspection emails.")


class ImageUploadConfig(BaseSettings):
	model_config = ConfigDict(frozen=True)

	DAY_IN_SECONDS: ClassVar[int] = 86400

	model_config = ConfigDict(frozen=True)
	api_key: str = Field(..., description="Upload Image API Key.")
	expiration: Optional[int] = Field(DAY_IN_SECONDS * 7, description="Optional expiration time in seconds.")



cfg : AppSettings = None

CONFIG = FOLDER / "config.yaml"


def path_representer(dumper, data):
  return dumper.represent_scalar(u'tag:yaml.org,2002:str', str(data))

yaml.add_representer(pathlib.PosixPath, path_representer)


def load():

	log.info(f"Loading Configuration at {CONFIG}")

	global cfg
	os.makedirs(FOLDER, exist_ok=True)
	
	if not CONFIG.exists():
		log.info("Config not found, creating default confgi")
		default_cfg = AppSettings()
		data = default_cfg.model_dump()

		with open(CONFIG, "w") as f:
			yaml.dump(data , f, sort_keys=False)
	
	# Load YAML
	with open(CONFIG, "r") as f:
		config_data = yaml.safe_load(f)
		cfg = AppSettings.model_validate(config_data)
		
	log.info(f"Configuration Loaded")

def get_config() -> AppSettings:
	return cfg

#rebuild model given settings order
AppSettings.model_rebuild()