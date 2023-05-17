import wap
from selenium import webdriver
from typing import Dict, List
import argparse


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "url",
        help="Url to request"
    )

    parser.add_argument(
        "--file",
        help="File with apps regexps",
        default="technologies.json"
    )

    return parser.parse_args()


def main():
    args = parse_args()
    technologies, _ = wap.load_file(args.file)

    browser = webdriver.Chrome()
    browser.get(args.url)
    url = browser.current_url
    cookies = parse_cookies_selenium(browser.get_cookies())
    html = browser.page_source
    scripts = extract_scripts_selenium(browser)
    metas = extract_metas_selenium(browser)
    browser.close()

    techno_matches = wap.discover_technologies(
        technologies,
        url=url,
        cookies=cookies,
        html=html,
        scripts=scripts,
        metas=metas
    )

    for t in techno_matches:
        fields = [t.technology.name]
        fields.append(t.version)
        fields.append(str(t.confidence))

        fields.append(",".join(
            [c.name for c in t.technology.categories]
        ))

        print(" ".join(fields))



if __name__ == '__main__':
    main()
