# tests/unit/test_time_source.py
"""时间源与时间戳校验单元测试。"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from sealium.common.time_source import (
    get_current_timestamp,
    get_timestamp_from_api,
    is_timestamp_valid,
)


class TestGetCurrentTimestamp:
    def test_returns_int_seconds(self):
        ts = get_current_timestamp()
        assert isinstance(ts, int)
        assert ts > 1_600_000_000  # 2020 年之后


class TestIsTimestampValid:
    def test_within_tolerance(self):
        assert is_timestamp_valid(1000, tolerance=10, now=1005) is True

    def test_outside_tolerance(self):
        assert is_timestamp_valid(1000, tolerance=10, now=1020) is False

    def test_boundaries_inclusive(self):
        assert is_timestamp_valid(1000, tolerance=10, now=1010) is True
        assert is_timestamp_valid(1000, tolerance=10, now=990) is True
        assert is_timestamp_valid(1000, tolerance=10, now=1011) is False

    def test_negative_skew(self):
        assert is_timestamp_valid(1000, tolerance=10, now=995) is True


class TestGetTimestampFromApi:
    def test_parses_timestamp(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"timestamp": 1700000000}
        mock_resp.raise_for_status.return_value = None
        with patch("sealium.common.time_source.requests.get", return_value=mock_resp) as mock_get:
            assert get_timestamp_from_api() == 1700000000
            mock_get.assert_called_once()

    def test_passes_timeout(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"timestamp": 1}
        mock_resp.raise_for_status.return_value = None
        with patch("sealium.common.time_source.requests.get", return_value=mock_resp) as mock_get:
            get_timestamp_from_api(timeout=7)
            assert mock_get.call_args.kwargs["timeout"] == 7

    def test_propagates_http_error(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = requests.HTTPError("500")
        with patch("sealium.common.time_source.requests.get", return_value=mock_resp):
            with pytest.raises(requests.HTTPError):
                get_timestamp_from_api()

    def test_propagates_network_error(self):
        with patch("sealium.common.time_source.requests.get", side_effect=requests.ConnectionError()):
            with pytest.raises(requests.ConnectionError):
                get_timestamp_from_api()
