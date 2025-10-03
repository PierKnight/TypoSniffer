from datetime import datetime
from pathlib import Path
from typing import Optional
from dataclasses import dataclass
from typosniffer.config.config import get_config
from typosniffer.data.database import DB
from typosniffer.data.dto import SuspiciousDomainDTO
from typosniffer.data.dto import WebsiteStatus
from typosniffer.data.tables import WebsiteRecord
from typosniffer.service import website_record
from typosniffer.sniffing import cnn
from typosniffer.utils import console, request
from typosniffer.utils import utility
from typosniffer.utils.logger import log
from typosniffer.utils.utility import expand_and_create_dir
from PIL import Image
import imagehash
import io
import asyncio
from playwright.async_api import Browser as PlayBrowser, BrowserContext, Page, TimeoutError as PageTimeoutError
from playwright.async_api import async_playwright



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



class DomainScreenshotBucket:

	def __init__(self, browser: PlayBrowser):
		self.images = {}
		self.locks = {}
		self.browser = browser

	async def _get_lock(self, key):
		if key not in self.locks:
			self.locks[key] = asyncio.Lock()
		return self.locks[key]

	async def get(self, domain: str):
		lock = await self._get_lock(domain)
		async with lock:
			image = self.images.get(domain)
			if image is None:
				image = await screenshot_page(self.browser, domain)
				self.images[domain] = image
			return image        

def save_screenshot(suspicious_domain: SuspiciousDomainDTO, date: datetime, screenshot: ScreenShotInfo) -> Path:


	image_file_path = website_record.get_screenshot(suspicious_domain=suspicious_domain, date=date)

	expand_and_create_dir(image_file_path.parent)

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
	cfg = get_config().inspection
	
	# Check if the new website record exists
	new_website_exist = new_record.screenshot_hash is not None
	
	# Check if the last recorded website was considered "up"
	# If there is no last record, assume it was not up
	last_website_exist = last_record.status.is_website_up() if last_record else False

	status = None  # Default status if no change is detected

	if new_website_exist:

		if last_website_exist:
			# Both last and new records exist; compare screenshots to detect changes
			difference = imagehash.hex_to_hash(last_record.screenshot_hash) - imagehash.hex_to_hash(new_record.screenshot_hash)
			
			# If the image difference exceeds the configured threshold, mark as changed
			if difference > cfg.hash_threshold:
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
				save_screenshot(domain, date, screenshot)
			return UpdateReport(date=date, url=new_record.website_url, status=new_status)

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


async def scan_domain(browser: PlayBrowser, domain: SuspiciousDomainDTO, screenshot_data: DomainScreenshotBucket, image_comparator: cnn.ImageComparator, semaphore: asyncio.Semaphore) -> DomainReport:

	async with semaphore:
		await asyncio.to_thread(utility.check_internet, throw=True)

		console.print_info(f'Inspecting {domain.name}')

		phish_screenshot = await screenshot_page(browser, domain.name)
		update_report = check_domain_updated(phish_screenshot, domain)
		phish_report = None
		if update_report is not None:
			real_screenshot = await screenshot_data.get(domain.original_domain.name)
			phish_report = check_domain_phishing(real_screenshot, phish_screenshot, image_comparator)

		
		return DomainReport(
			suspicious_domain = domain,
			update_report = update_report,
			phishing_report = phish_report
		)


def inspect_domains(domains: list[SuspiciousDomainDTO], max_workers: int = 4) -> list[DomainReport]:

	reports = asyncio.run(new_monitor(domains, max_workers))
	
	return reports

async def new_monitor(domains: list[SuspiciousDomainDTO], max_workers: int = 4) -> list[DomainReport]:

	semaphore = asyncio.Semaphore(max_workers)
	image_comparator = cnn.ImageComparator()

	async with async_playwright() as p:
		browser = await p.chromium.launch(headless=True)
		bucket = DomainScreenshotBucket(browser)
		
		tasks = [scan_domain(browser, domain, bucket, image_comparator, semaphore) for i, domain in enumerate(domains)]
		reports = await asyncio.gather(*tasks)
		await browser.close()
		return reports


async def screenshot_page(browser : PlayBrowser, domain: str) -> Optional[ScreenShotInfo]:
	
	#resolve url first
	url = await asyncio.to_thread(request.resolve_url, domain)

	#respect the maximum number of pages at the same time
	timeout_ms = get_config().inspection.page_load_timeout * 1000
	
	context: BrowserContext = await browser.new_context(user_agent=request.USER_AGENT)
	page: Page = await context.new_page()
	try:
		try:
			await page.goto(url, timeout=timeout_ms, wait_until='networkidle')
		except PageTimeoutError:
			console.print_error(f'Failed to screenshot {domain} page: try with wait')
			await page.goto(url, timeout=timeout_ms)
			await page.wait_for_timeout(2000)
		screenshot_bytes = await page.screenshot(full_page=True)
		
		image = await asyncio.to_thread(lambda: Image.open(io.BytesIO(screenshot_bytes)))
		url = page.url

		return ScreenShotInfo(image, url)
	except PageTimeoutError:
		console.print_error(f'Failed to screenshot {domain} page: timeout failed fallbacks')
	except Exception as e:
		if "ERR_NAME_NOT_RESOLVED" in str(e):
			console.print_error(f'Failed to screenshot {domain} page: not resolved')
		else:
			console.print_error(f'Failed to screenshot {domain} page: {e}')
			log.error(f"Screenshot error for {domain}", exc_info=True)
	finally:
		await context.close()
	return None


	