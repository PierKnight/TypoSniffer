import requests
from importlib.metadata import version


USER_AGENT = f"TypoSniffer/{version("typosniffer")}"



def get(url, **kargs):

    headers = kargs.pop("headers", {})
    headers.setdefault("User-Agent", USER_AGENT)
    
    response = requests.get(url, headers=headers, **kargs)
    response.raise_for_status()
    return response