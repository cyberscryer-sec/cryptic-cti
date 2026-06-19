from __future__ import annotations

import hashlib
import re
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from cryptic.file_utils import write_jsonl


def strip_html(text: str) -> str:
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def stable_record_id(source: str, stable_text: str, index: int) -> str:
    digest = content_hash(stable_text)[:12]
    safe_source = re.sub(r"[^a-z0-9]+", "_", source.lower()).strip("_") or "rss"
    return f"{safe_source}_{index:03d}_{digest}"


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def child_text(element: ET.Element, names: set[str]) -> str:
    for child in list(element):
        if local_name(child.tag) in names:
            return "".join(child.itertext()).strip()
    return ""


def child_attr(element: ET.Element, names: set[str], attr: str) -> str:
    for child in list(element):
        if local_name(child.tag) in names:
            return child.attrib.get(attr, "").strip()
    return ""


def record_from_item(item: ET.Element, index: int, feed_source: str) -> dict[str, Any]:
    title = child_text(item, {"title"})
    link = child_text(item, {"link"}) or child_attr(item, {"link"}, "href")
    published_at = child_text(item, {"pubdate", "published", "updated", "date"})
    summary = child_text(item, {"description", "summary", "content", "encoded"})
    raw_text = "\n".join(v for v in [title, strip_html(summary)] if v).strip()
    stable_text = link or raw_text or f"{feed_source}:{index}"
    ingest_status = "ingested" if raw_text else "missing_content"
    return {
        "id": stable_record_id(feed_source, stable_text, index),
        "source": "rss",
        "source_name": feed_source,
        "source_url": link,
        "title": title,
        "published_at": published_at,
        "raw_text": raw_text,
        "content_hash": content_hash(raw_text or stable_text),
        "ingest_status": ingest_status,
    }


def parse_feed_xml(xml_text: str, source_name: str = "rss_feed") -> list[dict[str, Any]]:
    root = ET.fromstring(xml_text)
    items = [el for el in root.iter() if local_name(el.tag) in {"item", "entry"}]
    return [record_from_item(item, index, source_name) for index, item in enumerate(items, start=1)]


def fetch_feed_text(feed_url_or_file: str | Path) -> tuple[str, str]:
    value = str(feed_url_or_file)
    if value.startswith(("http://", "https://")):
        with urllib.request.urlopen(value, timeout=20) as response:
            return response.read().decode("utf-8", errors="replace"), value
    path = Path(value)
    return path.read_text(encoding="utf-8"), path.stem


def ingest_feed(feed_url_or_file: str | Path, output_path: str | Path) -> Path:
    xml_text, source_name = fetch_feed_text(feed_url_or_file)
    records = parse_feed_xml(xml_text, source_name)
    output_path = Path(output_path)
    write_jsonl(output_path, records)
    return output_path
