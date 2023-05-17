from bs4 import BeautifulSoup
from typing import List, Dict, Any
from .match import discover_technologies
from .structs import Technology, TechMatch

def discover_requests_technologies(
        technologies: List[Technology],
        response
) -> List[TechMatch]:
    """Helper to discover the technologies in a HTTP response
    of the requests library.

    Example:
        >>> import wap
        >>> import requests
        >>> techs, _ = wap.load_file("technologies.json")
        >>> resp = requests.get("https://www.github.com")
        >>> t_matches = wap.discover_requests_technologies(techs, resp)
    """

    r = parse_requests_response(response)
    return discover_technologies(
        technologies,
        url=r["url"],
        headers=r["headers"],
        cookies=r["cookies"],
        html=r["html"],
        scripts=r["scripts"],
        metas=r["metas"]
    )

def parse_requests_response(response) -> Dict[str, Any]:
    """Helper to extract all the relevant information for wap
    from a HTTP response generated by requests library.

    Args:
        response: A response generated by the requests library.

    Returns:
        Dict[str, Any]: A dictionary with the keywords "url",
            "headers", "cookies", "html", "scripts" and "metas",
            with values ready to be used by wap.


    Example:
        >>> import wap
        >>> import requests
        >>> resp = requests.get("https://www.github.com")
        >>> resp_elements = wap.parse_requests_response(resp)


    """
    if "text/html" in response.headers.get("content-type", "").lower():
        html = response.text
        scripts = extract_scripts(html)
        metas = extract_metas(html)
    else:
        html = ""
        scripts = []
        metas = []

    return {
        "url": response.url,
        "headers": parse_requests_headers(response.headers),
        "cookies": parse_requests_cookies(response.cookies),
        "html": html,
        "scripts": scripts,
        "metas": metas
    }

def extract_scripts(html: str) -> List[str]:
    """Helper to extract the javascript scripts paths or URL
    includes in the HTML content.

    Example:
        >>> import wap
        >>> import requests
        >>> resp = requests.get("https://www.github.com")
        >>> scripts = wap.extract_scripts(resp.text)

    """
    soup = BeautifulSoup(html, "html.parser")
    script_tags = soup.findAll("script")

    scripts = []
    for script_tag in script_tags:
        try:
            src = script_tag.attrs["src"]
            if not src.startswith("data:text/javascript;"):
                scripts.append(src)
        except KeyError:
            pass

    return scripts


def extract_metas(html: str) -> Dict[str, str]:
    """Helper to extract the name and content of the meta tags
    included in HTML content.

    Example:
        >>> import wap
        >>> import requests
        >>> resp = requests.get("https://www.github.com")
        >>> metas = wap.extract_metas(resp.text)

    """
    soup = BeautifulSoup(html, "html.parser")
    meta_tags = soup.findAll("meta")

    metas = {}
    for meta_tag in meta_tags:
        try:
            key = meta_tag.attrs.get("name", None) \
                or meta_tag.attrs["property"]
            metas[key.lower()] = [meta_tag.attrs["content"]]
        except KeyError:
            continue

    return metas


def parse_requests_headers(headers) -> Dict[str, List[str]]:
    """Helper to parse the headers retrieved for a response
    produced by the requests library, and generate headers to
    be used by wap.

    Example:
        >>> import wap
        >>> import requests
        >>> resp = requests.get("https://www.github.com")
        >>> headers = wap.parse_requests_headers(resp.headers)
    """
    return {
        k.lower(): [v]
        for k, v in headers.items()
    }


def parse_requests_cookies(cookies) -> Dict[str, List[str]]:
    """Helper to parse the cookies retrieved for a response
    produced by the requests library, and generate cookies to
    be used by wap.

    Example:
        >>> import wap
        >>> import requests
        >>> resp = requests.get("https://www.github.com")
        >>> cookies = wap.parse_requests_cookies(resp.cookies)
    """
    cks = {}
    for cookie in cookies:
        if cookie.name not in cks:
            cks[cookie.name] = []
        cks[cookie.name].append(cookie.value)
    return cks



def parse_selenium_cookies(cookies) -> Dict[str, List[str]]:
    """Helper to parse the cookies retrieved for the
    selenium browser, and generate cookies to be used
    by wap.

    Example:
        >>> import wap
        >>> from selenium import webdriver
        >>> browser = webdriver.Chrome()
        >>> browser.get("https://www.github.com")
        >>> cookies = wap.parse_selenium_cookies(browser.get_cookies())
    """
    cks = {}
    for cookie in cookies:
        if cookie["name"] not in cks:
            cks[cookie["name"]] = []
        cks[cookie["name"]].append(cookie["value"])
    return cks


def extract_scripts_selenium(browser) -> List[str]:
    """Helper to extract the javascript scripts paths or URL
    from the selenium browser.

    Example:
        >>> import wap
        >>> from selenium import webdriver
        >>> browser = webdriver.Chrome()
        >>> browser.get("https://www.github.com")
        >>> scripts = wap.extract_scripts_selenium(browser)

    """
    scripts = []
    script_tags = browser.find_elements_by_tag_name("script")
    for script in script_tags:
        src = script.get_attribute("src")
        if src and not src.startswith("data:text/javascript;"):
            scripts.append(src)

    return scripts


def extract_metas_selenium(browser) -> Dict[str, str]:
    """Helper to extract the name and content of the meta tags
    from the selenium browser.

    Example:
        >>> from selenium import webdriver
        >>> browser = webdriver.Chrome()
        >>> browser.get("https://www.github.com")
        >>> metas = extract_metas_selenium(browser)

    """
    meta_tags = browser.find_elements_by_tag_name("meta")

    metas = {}
    for meta in meta_tags:
        key = meta.get_attribute("name") or meta.get_attribute("property")
        content = meta.get_attribute("content")
        if key:
            metas[key.lower()] = [content]

    return metas
