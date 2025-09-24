from io import BytesIO
import requests
from importlib.metadata import version
import asyncio
from playwright.async_api import async_playwright
from playwright.async_api import Browser as PlayBrowser
from PIL import Image
from typosniffer.service import suspicious_domain


USER_AGENT = f"TypoSniffer/{version("typosniffer")}"


WEBDRIVER_ARGUMENTS = (
		'--disable-dev-shm-usage',
		'--ignore-certificate-errors',
		'--headless=new',
#		'--incognito',
#		'--no-sandbox',
		'--disable-gpu',
		'--disable-extensions',
		'--disk-cache-size=0',
		'--aggressive-cache-discard',
		'--disable-notifications',
		'--disable-remote-fonts',
		'--disable-sync',
		'--window-size=1366,768',
		'--hide-scrollbars',
		'--disable-audio-output',
		'--dns-prefetch-disable',
		'--no-default-browser-check',
		'--disable-background-networking',
		'--enable-features=NetworkService,NetworkServiceInProcess',
		'--disable-background-timer-throttling',
		'--disable-backgrounding-occluded-windows',
		'--disable-breakpad',
		'--disable-client-side-phishing-detection',
		'--disable-component-extensions-with-background-pages',
		'--disable-default-apps',
		'--disable-features=TranslateUI',
		'--disable-hang-monitor',
		'--disable-ipc-flooding-protection',
		'--disable-prompt-on-repost',
		'--disable-renderer-backgrounding',
		'--force-color-profile=srgb',
		'--metrics-recording-only',
		'--no-first-run',
		'--password-store=basic',
		'--use-mock-keychain',
		'--disable-blink-features=AutomationControlled',
		)


def get(url, **kargs):

    headers = kargs.pop("headers", {})
    headers.setdefault("User-Agent", USER_AGENT)
    
    response = requests.get(url, headers=headers, **kargs)
    response.raise_for_status()
    return response

def post(url, **kargs):

    headers = kargs.pop("headers", {})
    headers.setdefault("User-Agent", USER_AGENT)
    
    response = requests.post(url, headers=headers, **kargs)
    response.raise_for_status()
    return response


def resolve_url(domain: str) -> str:
    # If user already gave scheme, just return it
    if domain.startswith(("http://", "https://")):
        return domain
    
    # Try HTTPS first
    https_url = f"https://{domain}"
    try:
        r = requests.head(https_url, timeout=3, allow_redirects=True)
        if r.status_code < 400: 
            return https_url
    except Exception:
        pass
    
    # Fall back to HTTP
    return f"http://{domain}"


async def process_page(browser : PlayBrowser, domain, semaphore):
	
	url = await asyncio.to_thread(resolve_url, domain.name)
	async with semaphore:
		context = await browser.new_context(user_agent=USER_AGENT)
		page = await context.new_page()
		print(f"OPENING PAGE {domain.name}")
		try:
			await page.goto(url)
			print(f"OPENING PAGE URL {domain.name}")
			screenshot_path = f'/home/kali/Desktop/{domain.name}.png'
			screenshot_bytes = await page.screenshot(path=screenshot_path, full_page=True)

			image = Image.open(BytesIO(screenshot_bytes))

			image.save(screenshot_path)

			print(page.url)
		except Exception as e:
			print(f"❌ Failed {domain.name}: {e}")
		finally:
			await context.close()
        

async def test():

	domains = suspicious_domain.get_all_suspicious_domains()

	semaphore = asyncio.Semaphore(5)

	async with async_playwright() as p:
		browser = await p.chromium.launch(headless=True, args=WEBDRIVER_ARGUMENTS)
		
		tasks = [process_page(browser, domain, semaphore) for i, domain in enumerate(domains)]
		await asyncio.gather(*tasks)
		await browser.close()