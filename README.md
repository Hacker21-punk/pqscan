<div align="center">

# 🔬 PQScan

### Post-Quantum Cryptographic Vulnerability Scanner

**Find it before the quantum computer does.**

[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat-square&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![NIST PQC](https://img.shields.io/badge/NIST-FIPS%20203%2F204%2F205-blue?style=flat-square)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![CNSA 2.0](https://img.shields.io/badge/NSA-CNSA%202.0-red?style=flat-square)](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF)

[Features](#features) · [Installation](#installation) · [Quick Start](#quick-start) · [Audit Reports](#audit-reports) · [Sample Reports](#sample-reports) · [API Server](#api-server) · [Documentation](#documentation)

---

<img src="https://github.com/user-attachments/assets/c98399ad-f709-4c3d-9640-c8c20502c357" width="600" alt="PQScan Terminal Output" />

</div>

---

## The Problem

Every RSA key, every ECDSA certificate, every Diffie-Hellman key exchange your servers negotiate today will be **completely broken** by a cryptographically relevant quantum computer running [Shor's algorithm](https://en.wikipedia.org/wiki/Shor%27s_algorithm).

**The timeline:**

| Year | Event |
|------|-------|
| **2024** | NIST finalizes FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) |
| **2025** | NSA CNSA 2.0: Prefer PQC for new systems |
| **2026** | First compliance audit deadlines |
| **2030** | CNSA 2.0: TLS must support quantum-safe key exchange |
| **2033** | CNSA 2.0: All protocols must be fully quantum-safe |
| **NOW** | [Harvest Now, Decrypt Later](https://en.wikipedia.org/wiki/Harvest_now,_decrypt_later) attacks are active |

Nation-state adversaries are **already recording encrypted traffic** for future decryption. If your data must remain confidential for more than 10 years — trade secrets, health records, financial data, attorney-client communications — the threat is **not future. It is present.**

PQScan tells you exactly where you stand.

---

## Features

### 🔍 Multi-Protocol Scanning

| Protocol | Ports | Detection |
|----------|-------|-----------|
| **TLS/HTTPS** | 443, 8443, 4443 | Cipher suites, key exchange, certificates |
| **SSH** | 22, 2222 | Host key algorithms, key exchange methods |
| **SMTP** | 25, 465, 587 | STARTTLS upgrade, cipher negotiation |
| **IMAP/POP3** | 143, 993, 110, 995 | STARTTLS, direct TLS |
| **Database** | 5432, 3306 | PostgreSQL, MySQL TLS |
| **Other** | 636, 853, 3389 | LDAPS, DNS-over-TLS, RDP |

### 🔐 Full Cipher Enumeration

- Tests every TLS version individually (SSL 3.0, TLS 1.0–1.3)
- Probes 40+ cipher suites one at a time
- Tests all key exchange groups including **PQC hybrids**:
  - X25519Kyber768Draft00
  - X25519MLKEM768
  - SecP256r1MLKEM768
- Detects server cipher order preference
- Identifies classically weak ciphers (3DES, RC4, NULL, EXPORT)

### 📜 Certificate Chain Analysis

- Full chain walk: Root CA → Intermediate → Leaf
- Key algorithm and size at every level
- Signature algorithm classification
- PQC and hybrid certificate detection (ML-DSA, SLH-DSA, composite signatures)
- OCSP, CRL, CT log verification
- Expiration and validity period analysis

### 📊 Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| **CLI** | (default) | Terminal with color-coded risk levels |
| **JSON** | `--format json` | CI/CD pipelines, automation |
| **HTML** | `--format html` | Shareable web reports |
| **PDF** | `--format pdf` | Executive summaries |
| **CBOM** | `--format cbom` | CycloneDX v1.6 Cryptographic Bill of Materials |
| **Audit PDF** | `--audit` | 7-page CISO-ready audit with kill list and roadmap |

### 🎯 CISO Audit Report

A single command generates a board-ready PDF containing:

- **Executive Summary** with quantum risk score (0–100)
- **Priority Kill List** — immediate actions ranked by impact
- **Cryptographic Bill of Materials** — every algorithm, certificate, and protocol
- **Migration Roadmap** — phased plan from quick wins to full PQC adoption
- **CNSA 2.0 Compliance Assessment** — pass/fail against every milestone
- **Audit Attestation** — signature-ready compliance statement

---

## Installation

### From Source (Recommended)

```bash
git clone https://github.com/Hacker21-punk/pqscan.git
cd pqscan
go build -o pqscan .
sudo mv pqscan /usr/local/bin/
