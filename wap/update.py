import os
import logging
import requests
import argparse
import json
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


DEFAULT_TARGET_FILE = os.path.expanduser("~/.wap/technologies.json")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Update the technologies rules used by wappy."
    )

    parser.add_argument(
        "--target-file",
        help="Where to put the target file",
        default=DEFAULT_TARGET_FILE,
    )

    parser.add_argument(
        "-k", "--insecure",
        help="Do not check certificate in connections",
        action="store_true",
    )

    parser.add_argument(
        "-v",
        dest="verbosity",
        help="Verbosity",
        action="count",
        default=0,
    )

    args = parser.parse_args()
    return args


def main():
    args = parse_args()
    init_log(args.verbosity)

    update_techs_file(
        target_file=args.target_file,
        insecure=args.insecure
    )
    print("Done")


def init_log(verbosity=0, log_file=None):

    if verbosity == 1:
        level = logging.WARN
    elif verbosity == 2:
        level = logging.INFO
    elif verbosity > 2:
        level = logging.DEBUG
    else:
        level = logging.CRITICAL

    logging.basicConfig(
        level=level,
        filename=log_file,
        format="%(levelname)s:%(name)s:%(message)s"
    )


def update_techs_file(target_file=None, insecure=False):
    filepath = target_file or DEFAULT_TARGET_FILE

    try:
        content = retrieve_definitions_file(insecure)
    except Exception as ex:
        logger.error("Error retrieving file from github: %s", ex)
        raise ex

    dirpath = os.path.dirname(filepath)
    os.makedirs(dirpath, exist_ok=True)
    write_file(target_file, content)

def retrieve_definitions_file(insecure):
    session = requests.Session()
    session.verify = not insecure

    technologies = retrieve_technologies(session)
    categories = retrieve_categories(session)

    schema = merge_into_json_schema(categories, technologies)
    return json.dumps(schema, indent=2).encode('utf-8')


def retrieve_technologies(session):
    techs_folder = "https://github.com/wappalyzer/wappalyzer/tree/master/src/technologies"
    res = session.get(techs_folder)
    soup = BeautifulSoup(res.text, "html.parser")
    filenames = [
        os.path.basename(a["href"])
        for a in
        soup.findAll("a", class_="js-navigation-open Link--primary")
    ]

    base_raw_url = "https://raw.githubusercontent.com/wappalyzer/wappalyzer/master/src/technologies"

    logger.info("{} technology files".format(len(filenames)))
    technologies = {}
    for filename in filenames:
        logger.info("Downloading file {}".format(filename))
        url = base_raw_url + "/" + filename
        res = session.get(url)
        technologies.update(res.json())

    return technologies


def merge_into_json_schema(categories, technologies):
    return {
        "$schema": "../schema.json",
        "categories": categories,
        "technologies": technologies
    }


def retrieve_categories(session):
    categories = session.get("https://raw.githubusercontent.com/wappalyzer/wappalyzer/master/src/categories.json").json()
    return categories



def write_file(filepath, content):
    with open(filepath, 'wb') as fo:
        fo.write(content)


if __name__ == '__main__':
    exit(main())
