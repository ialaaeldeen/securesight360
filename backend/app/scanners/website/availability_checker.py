from __future__ import annotations

from dataclasses import dataclass, field
from time import monotonic

import requests
import urllib3
from requests import Response
from requests.exceptions import RequestException, SSLError, TooManyRedirects

from app.core.config import settings
from app.utils.validators import validate_website_url


DEFAULT_USER_AGENT = (
    "CyberShield360/1.0 "
    "(Authorized Security Assessment Tool; Safe Availability Check)"
)


@dataclass(frozen=True, slots=True)
class AvailabilityCheckResult:
    """
    Structured result returned by the website availability checker.

    This result contains only safe, non-invasive HTTP evidence.
    """

    original_url: str
    final_url: str | None
    is_available: bool
    http_status_code: int | None
    response_time_ms: int | None
    raw_headers: dict[str, str] = field(default_factory=dict)
    error: str | None = None
    strict_tls_error: str | None = None
    used_tls_verification_fallback: bool = False


class WebsiteAvailabilityChecker:
    """
    Safe website availability checker.

    This checker performs one controlled HTTP GET request to determine whether
    the target website is reachable. It does not perform exploitation,
    fuzzing, brute forcing, crawling, or intrusive testing.
    """

    def __init__(self, timeout_seconds: int | None = None) -> None:
        self.timeout_seconds = timeout_seconds or settings.REQUEST_TIMEOUT_SECONDS
        self.request_headers = {
            "User-Agent": DEFAULT_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

    def check(self, target_url: str) -> AvailabilityCheckResult:
        """
        Run a safe availability check against a validated website URL.
        """

        normalized_url = validate_website_url(target_url)
        start_time = monotonic()

        try:
            with requests.get(
                normalized_url,
                headers=self.request_headers,
                timeout=self.timeout_seconds,
                allow_redirects=True,
                stream=True,
            ) as response:
                return self._build_result(
                    original_url=normalized_url,
                    response=response,
                    response_time_ms=self._calculate_response_time_ms(start_time),
                )

        except TooManyRedirects:
            return AvailabilityCheckResult(
                original_url=normalized_url,
                final_url=None,
                is_available=False,
                http_status_code=None,
                response_time_ms=self._calculate_response_time_ms(start_time),
                error="Too many redirects while checking website availability.",
            )

        except SSLError as error:
            if normalized_url.lower().startswith("https://"):
                return self._check_https_reachability_without_tls_verification(
                    normalized_url=normalized_url,
                    start_time=start_time,
                    strict_tls_error=error,
                )

            return AvailabilityCheckResult(
                original_url=normalized_url,
                final_url=None,
                is_available=False,
                http_status_code=None,
                response_time_ms=self._calculate_response_time_ms(start_time),
                error=f"Website availability check failed: {error}",
            )

        except RequestException as error:
            return AvailabilityCheckResult(
                original_url=normalized_url,
                final_url=None,
                is_available=False,
                http_status_code=None,
                response_time_ms=self._calculate_response_time_ms(start_time),
                error=f"Website availability check failed: {error}",
            )

    def _check_https_reachability_without_tls_verification(
        self,
        normalized_url: str,
        start_time: float,
        strict_tls_error: SSLError,
    ) -> AvailabilityCheckResult:
        """
        Confirm reachability when strict TLS trust verification fails.

        This fallback is used only to separate network reachability from TLS
        certificate trust. TLS remains evaluated by the dedicated SSL checker.
        """

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        try:
            with requests.get(
                normalized_url,
                headers=self.request_headers,
                timeout=self.timeout_seconds,
                allow_redirects=True,
                stream=True,
                verify=False,
            ) as response:
                return self._build_result(
                    original_url=normalized_url,
                    response=response,
                    response_time_ms=self._calculate_response_time_ms(start_time),
                    strict_tls_error=(
                        "Strict TLS verification failed during availability check: "
                        f"{strict_tls_error}"
                    ),
                    used_tls_verification_fallback=True,
                )

        except TooManyRedirects:
            return AvailabilityCheckResult(
                original_url=normalized_url,
                final_url=None,
                is_available=False,
                http_status_code=None,
                response_time_ms=self._calculate_response_time_ms(start_time),
                error=(
                    "Too many redirects while checking website availability after "
                    "strict TLS verification failed."
                ),
                strict_tls_error=str(strict_tls_error),
                used_tls_verification_fallback=True,
            )

        except RequestException as fallback_error:
            return AvailabilityCheckResult(
                original_url=normalized_url,
                final_url=None,
                is_available=False,
                http_status_code=None,
                response_time_ms=self._calculate_response_time_ms(start_time),
                error=(
                    "Website availability check failed after TLS reachability "
                    f"fallback: {fallback_error}"
                ),
                strict_tls_error=str(strict_tls_error),
                used_tls_verification_fallback=True,
            )

    @staticmethod
    def _calculate_response_time_ms(start_time: float) -> int:
        """
        Calculate elapsed request time in milliseconds.
        """

        return max(0, int((monotonic() - start_time) * 1000))

    @staticmethod
    def _normalize_headers(response: Response) -> dict[str, str]:
        """
        Convert response headers into a standard dictionary.
        """

        return {str(key): str(value) for key, value in response.headers.items()}

    def _build_result(
        self,
        original_url: str,
        response: Response,
        response_time_ms: int,
        strict_tls_error: str | None = None,
        used_tls_verification_fallback: bool = False,
    ) -> AvailabilityCheckResult:
        """
        Convert a successful HTTP response into a structured result.
        """

        return AvailabilityCheckResult(
            original_url=original_url,
            final_url=response.url,
            is_available=True,
            http_status_code=response.status_code,
            response_time_ms=response_time_ms,
            raw_headers=self._normalize_headers(response),
            error=None,
        )