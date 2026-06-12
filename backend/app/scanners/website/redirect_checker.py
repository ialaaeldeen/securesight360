from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import ParseResult, urlparse, urlunparse

import requests
from requests import Response
from requests.exceptions import RequestException, TooManyRedirects

from app.core.config import settings
from app.scanners.website.availability_checker import DEFAULT_USER_AGENT
from app.utils.validators import validate_website_url


@dataclass(frozen=True, slots=True)
class RedirectCheckResult:
    """
    Structured result for HTTP to HTTPS redirect verification.

    This checker performs one safe HTTP request to the same host to verify
    whether plain HTTP traffic is redirected to HTTPS. It does not crawl,
    brute-force paths, or perform intrusive testing.
    """

    original_url: str
    checked_url: str
    final_url: str | None
    redirects_to_https: bool | None
    http_status_code: int | None
    redirect_chain: list[str] = field(default_factory=list)
    error: str | None = None


class HTTPToHTTPSRedirectChecker:
    """
    Safe HTTP to HTTPS redirect checker.

    Business value:
    - Confirms whether users who type http:// are upgraded to https://.
    - Helps detect downgrade exposure and incomplete HTTPS enforcement.
    """

    def __init__(self, timeout_seconds: int | None = None) -> None:
        self.timeout_seconds = timeout_seconds or settings.REQUEST_TIMEOUT_SECONDS
        self.request_headers = {
            "User-Agent": DEFAULT_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

    def check(self, target_url: str) -> RedirectCheckResult:
        normalized_url = validate_website_url(target_url)
        checked_url = self._build_http_url(normalized_url)

        try:
            with requests.get(
                checked_url,
                headers=self.request_headers,
                timeout=self.timeout_seconds,
                allow_redirects=True,
                stream=True,
            ) as response:
                return self._build_result(
                    original_url=normalized_url,
                    checked_url=checked_url,
                    response=response,
                )

        except TooManyRedirects:
            return RedirectCheckResult(
                original_url=normalized_url,
                checked_url=checked_url,
                final_url=None,
                redirects_to_https=False,
                http_status_code=None,
                error="Too many redirects while checking HTTP to HTTPS redirection.",
            )

        except RequestException as error:
            return RedirectCheckResult(
                original_url=normalized_url,
                checked_url=checked_url,
                final_url=None,
                redirects_to_https=None,
                http_status_code=None,
                error=f"HTTP to HTTPS redirect check failed: {error}",
            )

    @classmethod
    def _build_http_url(cls, normalized_url: str) -> str:
        parsed = urlparse(normalized_url)
        hostname = parsed.hostname or parsed.netloc

        if not hostname:
            raise ValueError("Unable to extract hostname for redirect check.")

        hostname = hostname.encode("idna").decode("ascii").lower()
        path = parsed.path or "/"

        return urlunparse(
            ParseResult(
                scheme="http",
                netloc=hostname,
                path=path,
                params="",
                query="",
                fragment="",
            )
        )

    @staticmethod
    def _build_result(
        original_url: str,
        checked_url: str,
        response: Response,
    ) -> RedirectCheckResult:
        redirect_chain = [item.url for item in response.history] + [response.url]
        final_url = response.url
        redirects_to_https = final_url.lower().startswith("https://")

        return RedirectCheckResult(
            original_url=original_url,
            checked_url=checked_url,
            final_url=final_url,
            redirects_to_https=redirects_to_https,
            http_status_code=response.status_code,
            redirect_chain=redirect_chain,
            error=None,
        )
