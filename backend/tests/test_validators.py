import pytest

from app.utils.validators import (
    ValidationError,
    extract_domain_from_url,
    is_private_network_target,
    validate_authorization,
    validate_ip_or_subnet,
    validate_website_url,
)


def test_validate_authorization_returns_policy_message_when_confirmed() -> None:
    authorization_message = validate_authorization(True)

    assert "I confirm that I own this system" in authorization_message
    assert "explicit written permission" in authorization_message


def test_validate_authorization_raises_error_when_not_confirmed() -> None:
    with pytest.raises(ValidationError, match="Authorization confirmation is required"):
        validate_authorization(False)


@pytest.mark.parametrize(
    "input_url, expected_url",
    [
        ("https://example.com", "https://example.com"),
        ("http://example.com", "http://example.com"),
        ("  https://example.com/login  ", "https://example.com/login"),
    ],
)
def test_validate_website_url_accepts_valid_http_and_https_urls(
    input_url: str,
    expected_url: str,
) -> None:
    assert validate_website_url(input_url) == expected_url


@pytest.mark.parametrize(
    "invalid_url",
    [
        "",
        "   ",
        "ftp://example.com",
        "javascript:alert(1)",
        "file:///etc/passwd",
        "https://",
        "example.com",
    ],
)
def test_validate_website_url_rejects_invalid_urls(invalid_url: str) -> None:
    with pytest.raises(ValidationError):
        validate_website_url(invalid_url)


@pytest.mark.parametrize(
    "url, expected_domain",
    [
        ("https://www.example.com/login", "www.example.com"),
        ("http://example.com", "example.com"),
        ("https://sub.domain.com/path?id=1", "sub.domain.com"),
    ],
)
def test_extract_domain_from_url_returns_lowercase_domain(
    url: str,
    expected_domain: str,
) -> None:
    assert extract_domain_from_url(url) == expected_domain


@pytest.mark.parametrize(
    "target, expected_target",
    [
        ("192.168.56.101", "192.168.56.101/32"),
        ("192.168.56.0/27", "192.168.56.0/27"),
        ("10.0.0.5", "10.0.0.5/32"),
    ],
)
def test_validate_ip_or_subnet_accepts_safe_targets(
    target: str,
    expected_target: str,
) -> None:
    assert validate_ip_or_subnet(target) == expected_target


@pytest.mark.parametrize(
    "invalid_target",
    [
        "",
        "not-an-ip",
        "192.168.56.0/24",
        "10.0.0.0/8",
    ],
)
def test_validate_ip_or_subnet_rejects_invalid_or_large_targets(
    invalid_target: str,
) -> None:
    with pytest.raises(ValidationError):
        validate_ip_or_subnet(invalid_target)


@pytest.mark.parametrize(
    "target, expected_result",
    [
        ("192.168.56.0/27", True),
        ("10.0.0.1/32", True),
        ("172.16.0.1/32", True),
    ],
)
def test_is_private_network_target_identifies_private_targets(
    target: str,
    expected_result: bool,
) -> None:
    assert is_private_network_target(target) is expected_result