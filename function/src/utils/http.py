"""HTTP helper with timeout, retry, and exponential backoff.

Wraps ``requests`` so every external REST call shares consistent timeout and
retry behavior. Retries are attempted for transient failures (connection
errors, timeouts, and HTTP 429/5xx) with exponential backoff and jitter.
"""

from __future__ import annotations

import logging
import random
import time
from typing import Any, Dict, Optional

import requests

logger = logging.getLogger(__name__)

_RETRYABLE_STATUS = {429, 500, 502, 503, 504}


class HttpError(Exception):
    """Raised when an HTTP call ultimately fails after retries."""


def request_with_retry(
    method: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    json_body: Optional[Any] = None,
    params: Optional[Dict[str, Any]] = None,
    data: Optional[bytes] = None,
    timeout: float = 10.0,
    max_retries: int = 3,
    backoff_base: float = 0.5,
) -> requests.Response:
    """Perform an HTTP request, retrying transient failures with backoff.

    Raises:
        HttpError: If all attempts fail or a non-retryable error occurs.
    """
    attempt = 0
    last_exc: Optional[Exception] = None

    while attempt <= max_retries:
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                json=json_body,
                params=params,
                data=data,
                timeout=timeout,
                allow_redirects=False,
            )
            if response.status_code in _RETRYABLE_STATUS and attempt < max_retries:
                _sleep_backoff(attempt, backoff_base, response)
                attempt += 1
                continue
            return response
        except (requests.ConnectionError, requests.Timeout) as exc:
            last_exc = exc
            if attempt >= max_retries:
                break
            _sleep_backoff(attempt, backoff_base, None)
            attempt += 1
        except requests.RequestException as exc:  # non-retryable
            raise HttpError(f"HTTP request to {url} failed") from exc

    raise HttpError(
        f"HTTP request to {url} failed after {max_retries + 1} attempts"
    ) from last_exc


def _sleep_backoff(
    attempt: int,
    backoff_base: float,
    response: Optional[requests.Response],
) -> None:
    """Sleep using Retry-After if present, else exponential backoff + jitter."""
    delay: Optional[float] = None
    if response is not None:
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                delay = float(retry_after)
            except ValueError:
                delay = None
    if delay is None:
        delay = backoff_base * (2 ** attempt) + random.uniform(0, backoff_base)
    time.sleep(delay)
