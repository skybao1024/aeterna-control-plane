"""Closed locales shared by signed contact requests and email rendering."""

from typing import Literal

NotificationLocale = Literal["en", "zh-CN"]


def validate_notification_locale(value: str) -> NotificationLocale:
    if value == "en":
        return "en"
    if value == "zh-CN":
        return "zh-CN"
    raise ValueError("Unsupported contact notification locale")
