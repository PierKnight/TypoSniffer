from typing import Tuple
import requests
from importlib.metadata import version
from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.by import By

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


class Browser:
    
	def __init__(self, url: str, timeout: int):
        
		self.url = url

		chrome_options = webdriver.ChromeOptions()
		chrome_options.accept_insecure_certs = True

		for opt in WEBDRIVER_ARGUMENTS:
			chrome_options.add_argument(opt)
		
		
		self.driver = webdriver.Chrome(options=chrome_options)
		self.driver.execute_cdp_cmd('Network.setUserAgentOverride', {'userAgent':USER_AGENT})
		self.driver.set_page_load_timeout(timeout)

		WebDriverWait(self.driver, timeout).until(lambda d: d.execute_script("return document.readyState") == "complete")
          
	def screenshot(self) -> Tuple[bytes, str]:
		try:
			self.driver.get(self.url)
                  
			required_width = self.driver.execute_script('return document.body.parentNode.scrollWidth')
			required_height = self.driver.execute_script('return document.body.parentNode.scrollHeight')
			self.driver.set_window_size(required_width, required_height)
			
			screenshot = self.driver.find_element(By.TAG_NAME, "body").screenshot_as_png
                  
			return screenshot, self.driver.current_url

			#return self.driver.get_screenshot_as_png(), self.driver.current_url
		finally:
			self.driver.quit()
