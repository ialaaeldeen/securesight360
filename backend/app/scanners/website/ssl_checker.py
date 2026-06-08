from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import cast
from urllib.parse import ParseResult, urlparse

from app.core.config import settings
from app.utils.validators import validate_website_url


CertificateDict = dict[str, object]


@dataclass(frozen=True, slots=True)
class SSLCheckResult:
    """
    Structured result returned by the SSL/TLS certificate checker.

    This checker performs a safe certificate validation using Python's
    standard SSL library. It does not perform intrusive TLS testing,
    exploitation, brute forcing, or aggressive protocol checks.
    """

    https_enabled: bool
    ssl_valid: bool | None
    hostname: str
    port: int
    issuer: str | None = None
    subject: str | None = None
    expiry_date: datetime | None = None
    days_until_expiry: int | None = None
    protocol_version: str | None = None
    cipher: str | None = None
    error: str | None = None


class SSLChecker:
    """
    Safe SSL/TLS certificate checker for authorized website assessments.

    Responsibilities:
    - Validate the target URL.
    - Confirm whether HTTPS is enabled.
    - Establish a controlled TLS connection.
    - Validate the certificate using trusted system CAs.
    - Extract certificate issuer, subject, expiry date, TLS version, and cipher.
    - Return structured results without crashing the scanner.
    """

    DEFAULT_HTTPS_PORT = 443
    MIN_PORT = 1
    MAX_PORT = 65535

    def __init__(self, timeout_seconds: int | None = None) -> None:
        self.timeout_seconds = timeout_seconds or settings.REQUEST_TIMEOUT_SECONDS

    def check(self, target_url: str) -> SSLCheckResult:
        """
        Run a safe SSL/TLS certificate check for a website URL.
        """

        try:
            normalized_url = validate_website_url(target_url)
            parsed_url = urlparse(normalized_url)

            hostname = self._extract_hostname(parsed_url)
            port = self._extract_port(parsed_url)
            https_enabled = parsed_url.scheme == "https"

            if not https_enabled:
                return SSLCheckResult(
                    https_enabled=False,
                    ssl_valid=None,
                    hostname=hostname,
                    port=port,
                    error="HTTPS is not enabled because the URL does not use https://.",
                )

            if not hostname:
                return SSLCheckResult(
                    https_enabled=True,
                    ssl_valid=False,
                    hostname=hostname,
                    port=port,
                    error="Unable to extract a valid hostname from the URL.",
                )

            return self._perform_tls_check(hostname=hostname, port=port)

        except ssl.SSLCertVerificationError as error:
            return SSLCheckResult(
                https_enabled=True,
                ssl_valid=False,
                hostname=locals().get("hostname", ""),
                port=locals().get("port", self.DEFAULT_HTTPS_PORT),
                error=f"SSL certificate verification failed: {error.verify_message}",
            )

        except ssl.SSLError as error:
            return SSLCheckResult(
                https_enabled=True,
                ssl_valid=False,
                hostname=locals().get("hostname", ""),
                port=locals().get("port", self.DEFAULT_HTTPS_PORT),
                error=f"SSL/TLS handshake failed: {error}",
            )

        except OSError as error:
            return SSLCheckResult(
                https_enabled=True,
                ssl_valid=False,
                hostname=locals().get("hostname", ""),
                port=locals().get("port", self.DEFAULT_HTTPS_PORT),
                error=f"Unable to connect to SSL/TLS service: {error}",
            )

        except ValueError as error:
            return SSLCheckResult(
                https_enabled=False,
                ssl_valid=False,
                hostname=locals().get("hostname", ""),
                port=locals().get("port", self.DEFAULT_HTTPS_PORT),
                error=f"Invalid SSL/TLS check input or certificate data: {error}",
            )

    def _perform_tls_check(self, hostname: str, port: int) -> SSLCheckResult:
        """
        Establish a controlled TLS connection and collect certificate metadata.
        """

        context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)

        with socket.create_connection(
            (hostname, port),
            timeout=self.timeout_seconds,
        ) as tcp_socket:
            with context.wrap_socket(
                tcp_socket,
                server_hostname=hostname,
            ) as tls_socket:
                certificate = self._get_peer_certificate(tls_socket)
                expiry_date = self._extract_expiry_date(certificate)

                return SSLCheckResult(
                    https_enabled=True,
                    ssl_valid=True,
                    hostname=hostname,
                    port=port,
                    issuer=self._format_certificate_name(certificate.get("issuer")),
                    subject=self._format_certificate_name(certificate.get("subject")),
                    expiry_date=expiry_date,
                    days_until_expiry=self._calculate_days_until_expiry(expiry_date),
                    protocol_version=tls_socket.version(),
                    cipher=self._format_cipher(tls_socket.cipher()),
                    error=None,
                )

    @staticmethod
    def _get_peer_certificate(tls_socket: ssl.SSLSocket) -> CertificateDict:
        """
        Safely retrieve and validate the peer certificate.

        ssl.SSLSocket.getpeercert() can return None depending on connection
        state and parameters, so the result must be validated before use.
        """

        certificate = tls_socket.getpeercert()

        if not certificate:
            raise ValueError("No peer certificate was returned by the server.")

        if not isinstance(certificate, dict):
            raise ValueError("Unexpected certificate format returned by the server.")

        return cast(CertificateDict, certificate)

    @classmethod
    def _extract_port(cls, parsed_url: ParseResult) -> int:
        """
        Extract and validate the target port.

        If no port is provided, HTTPS port 443 is used.
        """

        try:
            port = parsed_url.port or cls.DEFAULT_HTTPS_PORT
        except ValueError as error:
            raise ValueError("URL contains an invalid port value.") from error

        if not cls.MIN_PORT <= port <= cls.MAX_PORT:
            raise ValueError(
                f"Port must be between {cls.MIN_PORT} and {cls.MAX_PORT}."
            )

        return port

    @staticmethod
    def _extract_hostname(parsed_url: ParseResult) -> str:
        """
        Extract and normalize the hostname.

        IDNA encoding supports internationalized domain names safely.
        """

        hostname = parsed_url.hostname

        if not hostname:
            return ""

        return hostname.encode("idna").decode("ascii").lower()

    @staticmethod
    def _extract_expiry_date(certificate: CertificateDict) -> datetime | None:
        """
        Extract the certificate expiry date from the notAfter field.
        """

        not_after = certificate.get("notAfter")

        if not isinstance(not_after, str):
            return None

        timestamp = ssl.cert_time_to_seconds(not_after)
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)

    @staticmethod
    def _calculate_days_until_expiry(expiry_date: datetime | None) -> int | None:
        """
        Calculate the number of days remaining before certificate expiry.
        """

        if expiry_date is None:
            return None

        remaining_time = expiry_date - datetime.now(timezone.utc)
        return max(0, remaining_time.days)

    @staticmethod
    def _format_certificate_name(field_value: object) -> str | None:
        """
        Convert certificate issuer/subject tuples into a readable string.
        """

        if not field_value:
            return None

        if not isinstance(field_value, tuple):
            return str(field_value)

        parts: list[str] = []

        try:
            for attribute_group in field_value:
                if not isinstance(attribute_group, tuple):
                    continue

                for attribute in attribute_group:
                    if not isinstance(attribute, tuple) or len(attribute) != 2:
                        continue

                    key, value = attribute
                    parts.append(f"{key}={value}")

        except (TypeError, ValueError):
            return str(field_value)

        return ", ".join(parts) if parts else None

    @staticmethod
    def _format_cipher(cipher_info: tuple[str, str, int] | None) -> str | None:
        """
        Format TLS cipher information into a readable string.
        """

        if cipher_info is None:
            return None

        cipher_name, protocol_version, secret_bits = cipher_info
        return f"{cipher_name} ({protocol_version}, {secret_bits} bits)"