import ipaddress
from urllib.parse import urlparse

from app.core.config import settings
from app.core.scan_policy import AUTHORIZED_SCAN_MESSAGE, MAX_ALLOWED_SUBNET_PREFIX


class ValidationError(ValueError):
    """
    Custom validation error for CyberShield360 input validation.
    """

    pass


def validate_authorization(authorization_confirmed: bool) -> str:
    """
    Ensure the user confirmed authorization before scanning.

    CyberShield360 must only scan systems owned by the user
    or systems where the user has explicit permission.
    """

    if not authorization_confirmed:
        raise ValidationError(
            "Authorization confirmation is required before starting any scan."
        )

    return AUTHORIZED_SCAN_MESSAGE


def validate_website_url(url: str) -> str:
    """
    Validate and normalize website URLs.

    Allowed:
        https://example.com
        http://example.com

    Not allowed:
        javascript:
        file:
        ftp:
        empty values
    """

    cleaned_url = url.strip()

    if not cleaned_url:
        raise ValidationError("Website URL cannot be empty.")

    parsed_url = urlparse(cleaned_url)

    if parsed_url.scheme not in {"http", "https"}:
        raise ValidationError("Website URL must start with http:// or https://.")

    if not parsed_url.netloc:
        raise ValidationError("Website URL must include a valid domain name.")

    return cleaned_url


def extract_domain_from_url(url: str) -> str:
    """
    Extract the domain from a validated website URL.

    Example:
        https://www.example.com/login -> www.example.com
    """

    parsed_url = urlparse(url)
    domain = parsed_url.hostname

    if not domain:
        raise ValidationError("Unable to extract domain from URL.")

    return domain.lower()


def validate_ip_or_subnet(target: str) -> str:
    """
    Validate an IP address or subnet.

    Examples:
        192.168.56.101
        192.168.56.0/27

    Large subnets are blocked by policy to prevent unsafe scanning.
    """

    cleaned_target = target.strip()

    if not cleaned_target:
        raise ValidationError("Network target cannot be empty.")

    try:
        network = ipaddress.ip_network(cleaned_target, strict=False)
    except ValueError as error:
        raise ValidationError("Invalid IP address or subnet.") from error

    if network.prefixlen < MAX_ALLOWED_SUBNET_PREFIX:
        raise ValidationError(
            f"Subnet is too large. Maximum allowed subnet size is /{MAX_ALLOWED_SUBNET_PREFIX}."
        )

    if network.num_addresses > settings.MAX_NETWORK_TARGETS:
        raise ValidationError(
            f"Too many network targets. Maximum allowed targets: {settings.MAX_NETWORK_TARGETS}."
        )

    return str(network)


def is_private_network_target(target: str) -> bool:
    """
    Check whether the network target is private/internal.

    This is useful for encouraging lab-safe testing.
    Public IP scanning should only be done with explicit authorization.
    """

    network = ipaddress.ip_network(target, strict=False)
    return network.is_private