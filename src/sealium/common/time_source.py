# src/sealium/common/time_source.py
"""
时间戳来源与校验。

* 本地时间：``get_current_timestamp``
* 权威时间：``get_timestamp_from_api``（远程 API，可能抛网络异常）
* 校验：``is_timestamp_valid``，``now`` 可注入便于测试
"""

from __future__ import annotations

import time

import requests

from sealium.common.constants import REQUEST_TIMEOUT_SECONDS, TIMESTAMP_API_URL


def get_current_timestamp() -> int:
    """本地系统当前 Unix 时间戳（秒）。"""
    return int(time.time())


def get_timestamp_from_api(timeout: int = REQUEST_TIMEOUT_SECONDS) -> int:
    """
    从远程权威 API 获取 Unix 时间戳（秒）。

    :raises requests.RequestException: 网络或 HTTP 错误时抛出。
    """
    resp = requests.get(TIMESTAMP_API_URL, timeout=timeout)
    resp.raise_for_status()
    return int(resp.json()["timestamp"])


def is_timestamp_valid(
    timestamp: int, tolerance: int = 300, now: int | None = None
) -> bool:
    """
    检查时间戳是否在允许偏差范围内。

    :param now: 当前时间戳；为 ``None`` 时取本地时间。可注入便于测试。
    """
    current = now if now is not None else get_current_timestamp()
    return abs(current - timestamp) <= tolerance
