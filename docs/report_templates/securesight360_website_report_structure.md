# SecureSight360 Website Security Assessment Report Structure

## Purpose

This document defines the official structure for generated SecureSight360 website security assessment PDF reports.

The PDF report must be professional, client-ready, clear, and suitable for cybersecurity assessment delivery. It must not expose unnecessary raw JSON or unformatted scanner output.

---

## Report Branding

### Header / Letterhead

Every report must include:

- SecureSight360 logo
- SecureSight360 name
- Report title: Professional Website Security Assessment Report
- Confidentiality label

Recommended header text:

SecureSight360
Professional Cybersecurity Assessment Platform

### Footer

Every page must include:

© 2026 SecureSight360. All rights reserved.
Confidential Security Assessment Report.
Page number.

---

## Page 1 - Cover Summary

Required content:

- SecureSight360 logo
- Report title
- Target URL
- Scan ID
- Report date
- Prepared for user/company
- Security Rating
- Security Score
- Risk Level
- Scan status

Example:

Target: https://example.com
Security Rating: Weak
Security Score: 34/100
Risk Level: High
Report Date: 2026-06-13
Prepared For: user@company.com

---

## Page 2 - Executive Summary

Required content:

- Short executive summary
- Overall security posture
- Main risk explanation
- Business impact
- Plain-language explanation for non-technical readers

Tone:

Professional, direct, and client-friendly.

Avoid:

- Raw JSON
- Stack traces
- Developer-only field names
- Unexplained technical jargon

---

## Page 3 - Security Rating Overview

Required content:

- Security Score
- Security Rating
- Risk Level
- Rating explanation

Official Security Ratings:

- Excellent
- Strong
- Moderate
- Weak
- Critical

Recommended score mapping:

- 85-100: Excellent
- 70-84: Strong
- 50-69: Moderate
- 30-49: Weak
- 0-29: Critical

Recommended risk mapping:

- 70-100: Low
- 50-69: Medium
- 30-49: High
- 0-29: Critical

---

## Page 4 - Key Findings and Priority Actions

Required content:

- Key findings
- Severity or risk label
- Why it matters
- Recommendation
- Evidence summary

Each finding should use this format:

Finding:
Risk:
Why it matters:
Recommendation:
Evidence:

---

## Page 5 - Technical Evidence

Required content where available:

- HTTPS / TLS status
- SSL certificate status
- HTTP to HTTPS redirect behavior
- Security headers
- DNS records
- SPF / DMARC email security status
- Technologies detected

Technical evidence must be summarized cleanly. Do not dump raw nested scanner data.

---

## Final Page - Methodology, Authorization, and Disclaimer

Required content:

### Methodology

SecureSight360 performs a non-invasive website security assessment using passive and safe checks such as availability, HTTPS/TLS, security headers, DNS/email security records, and risk scoring.

### Authorization Statement

This report is generated only for assets where the user confirmed they are authorized to perform the assessment.

### Disclaimer

This report is not a full penetration test. Results are based on the evidence available at scan time. Security posture may change after the scan date.

### Confidentiality

This report may contain sensitive security information and should only be shared with authorized stakeholders.

---

## Output Requirements

The generated PDF must:

- Use the SecureSight360 brand
- Include logo when available
- Include page headers and footers
- Use clear section headings
- Show Security Rating instead of raw backend grade wording
- Use professional tables where appropriate
- Avoid broken layout, clipped text, and overlapping sections
- Retain audit-friendly scan ID and authorization statement
