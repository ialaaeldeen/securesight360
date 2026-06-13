from __future__ import annotations

from dataclasses import dataclass, field

import dns.exception
import dns.resolver

from app.core.config import settings


@dataclass(frozen=True, slots=True)
class DNSCheckResult:
    """
    Structured result returned by the DNS checker.

    The checker performs safe DNS lookups only. It does not perform
    zone transfers, brute-force subdomain discovery, or intrusive DNS testing.
    """

    domain: str
    records: dict[str, list[str]] = field(default_factory=dict)
    spf_found: bool | None = None
    dmarc_found: bool | None = None
    caa_found: bool | None = None
    caa_records: list[str] = field(default_factory=list)
    caa: dict[str, object] = field(default_factory=dict)
    dkim_guidance: str | None = None
    errors: dict[str, str] = field(default_factory=dict)


class DNSChecker:
    """
    Safe DNS and email security record checker.

    Responsibilities:
    - Query common DNS records safely.
    - Check SPF record presence from TXT records.
    - Check DMARC record presence from _dmarc.domain.
    - Check CAA records for certificate issuance control.
    - Provide DKIM guidance without guessing selectors aggressively.
    """

    DEFAULT_RECORD_TYPES: tuple[str, ...] = ("A", "AAAA", "MX", "NS", "TXT", "CAA")

    def __init__(self, timeout_seconds: int | None = None) -> None:
        self.timeout_seconds = timeout_seconds or settings.REQUEST_TIMEOUT_SECONDS
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = self.timeout_seconds
        self.resolver.lifetime = self.timeout_seconds

    def check(self, domain: str) -> DNSCheckResult:
        """
        Run safe DNS and email security checks for a domain.
        """

        normalized_domain = self._normalize_domain(domain)

        records: dict[str, list[str]] = {}
        errors: dict[str, str] = {}

        for record_type in self.DEFAULT_RECORD_TYPES:
            record_values, error = self._query_records(
                domain=normalized_domain,
                record_type=record_type,
            )

            records[record_type] = record_values

            if error:
                errors[record_type] = error

        spf_found = self._has_spf_record(records.get("TXT", []))
        dmarc_records, dmarc_error = self._query_records(
            domain=f"_dmarc.{normalized_domain}",
            record_type="TXT",
        )

        records["DMARC"] = dmarc_records

        if dmarc_error:
            errors["DMARC"] = dmarc_error

        dmarc_found = self._has_dmarc_record(dmarc_records)

        caa_records = records.get("CAA", [])
        caa_found = self._has_caa_record(caa_records)
        caa_evidence = {
            "present": caa_found,
            "records": caa_records,
            "value": "; ".join(caa_records) if caa_records else None,
            "status": "present" if caa_found else "missing",
        }

        return DNSCheckResult(
            domain=normalized_domain,
            records=records,
            spf_found=spf_found,
            dmarc_found=dmarc_found,
            caa_found=caa_found,
            caa_records=caa_records,
            caa=caa_evidence,
            dkim_guidance=self._build_dkim_guidance(normalized_domain),
            errors=errors,
        )

    def _query_records(
        self,
        domain: str,
        record_type: str,
    ) -> tuple[list[str], str | None]:
        """
        Query DNS records safely and return values plus optional error.
        """

        try:
            answers = self.resolver.resolve(domain, record_type)
            return [self._format_dns_answer(answer) for answer in answers], None

        except dns.resolver.NoAnswer:
            return [], f"No {record_type} records found."

        except dns.resolver.NXDOMAIN:
            return [], f"Domain does not exist while querying {record_type} records."

        except dns.resolver.NoNameservers:
            return [], f"No nameservers available for {record_type} lookup."

        except dns.exception.Timeout:
            return [], f"DNS lookup timed out for {record_type} records."

        except dns.exception.DNSException as error:
            return [], f"DNS lookup failed for {record_type} records: {error}"

    @staticmethod
    def _normalize_domain(domain: str) -> str:
        """
        Normalize a domain name for DNS lookups.
        """

        cleaned_domain = domain.strip().lower().rstrip(".")

        if not cleaned_domain:
            raise ValueError("Domain cannot be empty.")

        return cleaned_domain.encode("idna").decode("ascii")

    @staticmethod
    def _format_dns_answer(answer: object) -> str:
        """
        Convert a DNS answer object into a clean string value.
        """

        return str(answer).strip().strip('"')

    @staticmethod
    def _has_spf_record(txt_records: list[str]) -> bool:
        """
        Check whether TXT records contain an SPF policy.
        """

        return any(record.lower().startswith("v=spf1") for record in txt_records)

    @staticmethod
    def _has_dmarc_record(txt_records: list[str]) -> bool:
        """
        Check whether DMARC TXT records contain a DMARC policy.
        """

        return any(record.lower().startswith("v=dmarc1") for record in txt_records)

    @staticmethod
    def _has_caa_record(caa_records: list[str]) -> bool:
        """
        Check whether CAA records are published for certificate issuance control.
        """

        return bool(caa_records)

    @staticmethod
    def _build_dkim_guidance(domain: str) -> str:
        """
        Provide safe DKIM guidance.

        DKIM records require knowing the selector, and selector guessing can
        become noisy. The MVP provides guidance instead of brute-forcing selectors.
        """

        return (
            "DKIM requires a known selector, such as selector1._domainkey."
            f"{domain}. Verify DKIM through your email provider or authorized "
            "mail administration panel."
        )