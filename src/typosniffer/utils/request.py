import requests
from importlib.metadata import version
from selenium import webdriver


USER_AGENT = f"TypoSniffer/{version("typosniffer")}"


WEBDRIVER_ARGUMENTS = (
		'--disable-dev-shm-usage',
		'--ignore-certificate-errors',
		'--headless',
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
        print(r.status_code)
        print(r.text)
        if r.status_code < 400: 
            return https_url
    except Exception:
        pass
    
    # Fall back to HTTP
    return f"http://{domain}"

def website_screenshot(url: str, timeout: int) -> bytes:

    chrome_options = webdriver.ChromeOptions()
    chrome_options.accept_insecure_certs = True

    for opt in WEBDRIVER_ARGUMENTS:
        chrome_options.add_argument(opt)
     
    driver = webdriver.Chrome(options=chrome_options)
    driver.execute_cdp_cmd('Network.setUserAgentOverride', {'userAgent':USER_AGENT})
    driver.set_page_load_timeout(timeout)
    try:
        driver.get(url)
        return driver.get_screenshot_as_png()
    finally:
    	driver.quit()