"""Static notice instructions never read a capability or mutate test authority."""

import html

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

from app.services.common.aeterna_trigger_test_copy import trigger_test_copy

router = APIRouter()


@router.get("/trigger-tests/notice", include_in_schema=False)
async def trigger_test_notice():
    paragraphs = []
    for locale in ("en", "zh-CN"):
        copy = trigger_test_copy(locale)
        paragraphs.append(
            f'<section lang="{locale}"><h1>{html.escape(copy["landingTitle"])}</h1><p>{html.escape(copy["landingBody"])}</p></section>'
        )
    return HTMLResponse(
        '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Aeterna Relay</title></head><body>'
        + "".join(paragraphs)
        + "</body></html>",
        headers={
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
            "Referrer-Policy": "no-referrer",
        },
    )
