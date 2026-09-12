import csv
import time
from datetime import datetime
from urllib.parse import urlparse

import bleach
import pandas as pd
from docx import Document
from PyPDF2 import PdfReader

from app.exceptions.http_exceptions import APIException

# Allowed file types
ALLOWED_AUDIO_TYPES = ["mp3", "wav", "ogg", "m4a", "flac"]


def extract_docx_text(file_path):
    """
    Extract text content from DOCX file
    """
    doc = Document(file_path)
    full_text = []
    for para in doc.paragraphs:
        full_text.append(para.text)
    return "\n".join(full_text)


def extract_pdf_text(file_path: str) -> str:
    """
    Extract text content from PDF file
    """
    try:
        reader = PdfReader(file_path)
        text_content = []

        # Iterate through each page and extract text
        for page in reader.pages:
            text_content.append(page.extract_text())

        return "\n".join(text_content)
    except Exception as e:
        raise APIException(
            status_code=400, message=f"PDF file parsing failed: {str(e)}"
        )


def process_csv_file(file_path: str) -> str:
    """
    Process CSV file and return formatted text content
    """
    try:
        # Try using pandas to read (can handle more complex CSV)
        try:
            df = pd.read_csv(file_path)
            # Get basic statistics
            summary = f"CSV file summary:\n"
            summary += f"Total rows: {len(df)}\n"
            summary += f"Total columns: {len(df.columns)}\n"
            summary += f"Column names: {', '.join(df.columns)}\n\n"

            # Add first few rows as preview
            preview_rows = min(5, len(df))
            summary += f"First {preview_rows} rows preview:\n"
            summary += df.head(preview_rows).to_string()

            return summary

        except Exception:
            # If pandas reading fails, use csv module as fallback
            with open(file_path, "r", encoding="utf-8") as f:
                csv_reader = csv.reader(f)
                headers = next(csv_reader)  # Get headers
                rows = list(csv_reader)[:5]  # Get first 5 rows of data

                content = f"CSV file content:\n"
                content += f"Headers: {', '.join(headers)}\n\n"
                content += "Data preview:\n"
                for row in rows:
                    content += f"{', '.join(row)}\n"

                return content

    except Exception as e:
        raise APIException(
            status_code=400, message=f"CSV file parsing failed: {str(e)}"
        )


def process_audio_file(file_path: str) -> str:
    """
    Process audio file and return transcription text
    """
    import os

    import whisper

    try:
        # Ensure file path is absolute and properly encoded
        absolute_path = os.path.abspath(os.path.normpath(file_path))

        # Convert file path to raw string
        safe_path = str(absolute_path)

        # Load Whisper model
        model = whisper.load_model("base")

        # Transcribe audio
        result = model.transcribe(safe_path)

        return result["text"]

    except Exception as e:
        raise APIException(
            status_code=400, message=f"Audio transcription failed: {str(e)}"
        )


def validate_remote_url(url: str) -> bool:
    """Validate if remote URL is valid"""
    try:
        parsed = urlparse(url)
        return all([parsed.scheme, parsed.netloc])
    except Exception as e:
        raise APIException(
            status_code=400, message=f"Verification of remote URL failed: {str(e)}"
        )


# HTML sanitization function
def sanitize_html(html_content):
    allowed_tags = [
        "p",
        "br",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "strong",
        "em",
        "u",
        "ul",
        "ol",
        "li",
        "span",
        "a",
        "img",
        "blockquote",
        "code",
        "pre",
        "table",
        "thead",
        "tbody",
        "tr",
        "th",
        "td",
        "div",
    ]
    allowed_attrs = {
        "*": ["class", "style"],
        "a": ["href", "rel", "target"],
        "img": ["src", "alt", "width", "height"],
        "table": ["border", "cellpadding", "cellspacing"],
        "th": ["colspan", "rowspan"],
        "td": ["colspan", "rowspan"],
    }
    cleaned_html = bleach.clean(
        html_content, tags=allowed_tags, attributes=allowed_attrs, strip=True
    )
    return cleaned_html


# HTTP proxy configuration tool
def configure_http_proxy():
    """
    Configure HTTP proxy, only enabled in test environment

    Returns:
        httpx.Client: httpx client configured with proxy, or default client if proxy not needed
    """
    import os

    import httpx

    from ..core.config import settings

    # Enable proxy only in test environment
    if settings.ENV == "development" and settings.USE_HTTP_PROXY:
        # Set environment variables
        os.environ["HTTP_PROXY"] = settings.HTTP_PROXY
        os.environ["HTTPS_PROXY"] = settings.HTTPS_PROXY

        # Create httpx client configured with proxy
        # Note: proxy URL format in httpx should be complete URL
        proxy_url = settings.HTTP_PROXY
        proxy_client = httpx.Client(proxy=proxy_url)
        return proxy_client
    else:
        # In non-development environment or when proxy is not enabled, explicitly remove proxy environment variables
        if "HTTP_PROXY" in os.environ:
            del os.environ["HTTP_PROXY"]
        if "HTTPS_PROXY" in os.environ:
            del os.environ["HTTPS_PROXY"]
        if "http_proxy" in os.environ:
            del os.environ["http_proxy"]
        if "https_proxy" in os.environ:
            del os.environ["https_proxy"]

    # Return an httpx client explicitly configured without proxy
    return httpx.Client(timeout=60.0)


def convert_to_timestamp(date_value):
    if date_value is None:
        return None

    try:
        # Try to parse the date string - adjust the format as needed
        # This example assumes date format like "2025-03-11" or "2025/03/11"
        if isinstance(date_value, str):
            # Try multiple common date formats
            for fmt in ["%Y-%m-%d", "%Y/%m/%d", "%d-%m-%Y", "%d/%m/%Y"]:
                try:
                    date_obj = datetime.strptime(date_value, fmt)
                    # Convert to integer timestamp (seconds since epoch)
                    return int(time.mktime(date_obj.timetuple()))
                except ValueError:
                    continue

        # If it's already a datetime object
        elif isinstance(date_value, datetime):
            return int(time.mktime(date_value.timetuple()))

        # If the conversion failed
        return None
    except:
        return None
