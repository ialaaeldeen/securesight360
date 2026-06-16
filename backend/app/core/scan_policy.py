"""
SecureSight360 ethical scanning policy.

This file defines the safety rules used by the platform.
SecureSight360 must only scan systems owned by the user
or systems where the user has explicit written permission.
"""

AUTHORIZED_SCAN_MESSAGE = (
    "I confirm that I own this system or have explicit written permission "
    "to perform this security assessment. I understand that unauthorized "
    "scanning may be illegal and against service provider policies."
)


SAFE_WEBSITE_CHECKS = [
    "availability_check",
    "https_check",
    "ssl_certificate_check",
    "security_headers_check",
    "dns_record_check",
    "email_security_record_check",
    "basic_technology_detection",
]


SAFE_NETWORK_CHECKS = [
    "host_discovery",
    "top_ports_scan",
    "service_detection_light",
    "open_port_risk_mapping",
]


BLOCKED_SCAN_TYPES = [
    "bruteforce",
    "password_attack",
    "credential_stuffing",
    "exploit_execution",
    "denial_of_service",
    "sql_injection_attack",
    "xss_payload_attack",
    "directory_bruteforce",
    "malware_execution",
]


SAFE_NMAP_ARGUMENTS = [
    "-sV",
    "--version-light",
    "--top-ports",
]


MAX_ALLOWED_SUBNET_PREFIX = 27
"""
/27 allows up to 32 IP addresses.

This keeps network scanning controlled and prevents large-range scanning.
For example:
    192.168.56.0/27 = allowed
    192.168.56.0/24 = too large for this project safety policy
"""


def is_blocked_scan_type(scan_type: str) -> bool:
    """
    Check whether a requested scan type is blocked by policy.
    """

    normalized_scan_type = scan_type.strip().lower()
    return normalized_scan_type in BLOCKED_SCAN_TYPES


def get_authorization_message() -> str:
    """
    Return the standard authorization message shown to users.
    """

    return AUTHORIZED_SCAN_MESSAGE