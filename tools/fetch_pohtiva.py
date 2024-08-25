#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Convert documents from Pohtiva & convert to Markdown

Install dependencies:

    pip install -r requirements.txt

Usage:

    python3 fetch_pohtiva.py

should produce Markdown files in year-based structure below current directory.
"""

import datetime
import os
import requests
import sys
import time
import yaml

try:
    import requests_cache
    requests_cache.install_cache('pohtiva', expire_after=864000)
except ImportError:
    pass

from lxml import etree
from lxml import html

from markdownify import markdownify
from slugify import slugify


class HTMLParser:
    def __init__(self, url: str):
        self.url = url
        headers = {
            'User-Agent': 'Fetch-Pohtiva/1.0 (+https://github.com/ypcs/vihreat-ohjelmat)'
        }
        res = requests.get(url, headers=headers)
        res.raise_for_status()
        self._parser = etree.HTMLParser()
        self.tree = etree.parse(res.raw, self._parser)


class Document:
    def __init__(self, *, title: str, year: int, party: str, type: str,
                 language: str, url: str):
        self.title = title.strip()
        self.year = int(year)
        self.party = party.strip()
        self.type = type.strip()
        self.url = url.strip()
        self.language = language.strip()

    def __str__(self):
        return f'{self.title} ({self.party}, {self.year}) <{self.url}>'

    def fetch(self):
        time.sleep(0.5)
        tree = HTMLParser(url=self.url).tree
        main = tree.xpath('//main')[0]
        content = main.xpath("//div[@class='platform']")
        self.content = html.tostring(content[0])
        self.timestamp = datetime.datetime.now()
        self.ref = f'Puolueohjelmien tietokanta POHTIVA [verkkojulkaisu]. Tampere: Yhteiskuntatieteellinen tietoarkisto [ylläpitäjä ja tuottaja]. <https://www.fsd.tuni.fi/pohtiva>. (Viitattu {datetime.datetime.now():%Y-%m-%d}.)'

    def _get_frontmatter(self):
        """Format frontmatter for Markdown files"""
        attrs = ['title', 'year', 'party', 'type', 'url', 'timestamp', 'ref',
                 'language']
        delim = '---'
        data = {k: getattr(self, k) for k in attrs}
        return f'{delim}\n{yaml.dump(data)}{delim}\n'

    def as_markdown(self):
        """Return meta + contents as Markdown"""
        md = markdownify(self.content, wrap=False, heading_style='ATX')
        return '\n'.join([self._get_frontmatter(), md])

    def get_filename(self):
        return f'{self.year}/{slugify(self.title)}.md'


class Pohtiva:
    def __init__(self, url):
        self.url = url

    def _get_tree(self, url: str):
        parser = etree.HTMLParser()
        res = requests.get(url)
        return etree.parse(res.raw, parser)

    def get_document_list(self):
        """Get list of all available documents"""
        # Table of contents: first <table> in <main>, and we expect just one
        # table to be found
        tree = self._get_tree(self.url)
        toc = tree.xpath('//main//table')
        if len(toc) != 1:
            raise ValueError("Could not find table of contents.")
        # Parse the table
        items = []
        rows = toc[0].xpath('//tbody/tr')
        print(f"Found {len(rows)} documents.")
        for row in rows:
            cols = row
            link = cols[0].xpath('a')[0]
            item = {
                'title': link.text.strip(),
                'url': link.get('href'),
                'party': cols[1].text.strip(),
                'year': int(cols[2].text),
                'type': cols[3].text.strip(),
                'language': cols[4].text.strip(),
            }
            doc = Document(**item)
            items.append(doc)
        return items


def main():
    api = Pohtiva('https://www.fsd.tuni.fi/pohtiva/ohjelmalistat/VIHR')

    docs = api.get_document_list()
    for doc in docs:
        print(doc)
        fn = doc.get_filename()
        doc.fetch()
        d = os.path.dirname(fn)
        os.makedirs(d, exist_ok=True)
        with open(fn, 'w', encoding='utf-8') as f:
            f.write(doc.as_markdown())
            print(f"Wrote {fn}.")


if __name__ == '__main__':
    sys.exit(main())
