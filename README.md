<div align="center">

# ⚛ pqscan

### Post-Quantum Cryptography Vulnerability Scanner

**Find your quantum-vulnerable encryption before a quantum computer does.**

[![Quantum Scan](https://github.com/Hacker21-punk/pqscan/actions/workflows/quantum-scan.yml/badge.svg)](https://github.com/Hacker21-punk/pqscan/actions/workflows/quantum-scan.yml)
[![Go Version](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![CNSA 2.0](https://img.shields.io/badge/CNSA_2.0-Compliant_Checker-purple)](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF)
[![CycloneDX](https://img.shields.io/badge/CycloneDX-CBOM_v1.6-brightgreen)](https://cyclonedx.org/capabilities/cbom/)

<br>

*The largest cryptographic migration in history is coming.*
*It starts with knowing what you have.*

<br>

[Quick Start](#-quick-start) •
[Features](#-features) •
[Output Formats](#-output-formats) •
[GitHub Actions](#-github-actions) •
[Why This Matters](#-why-this-matters)

</div>

---

## 🔴 The Problem

**94%+ of internet endpoints** use encryption that quantum computers will break.

| Threat | What It Breaks | Impact |
|--------|---------------|--------|
| **Shor's Algorithm** | RSA, ECDSA, ECDH, Diffie-Hellman | Private keys recovered. All traffic decryptable. Signatures forgeable. |
| **Grover's Algorithm** | AES-128, SHA-256 | Security halved. AES-128 → 64-bit (broken). AES-256 → 128-bit (safe). |
| **Harvest Now, Decrypt Later** | Everything transmitted today | Adversaries record encrypted traffic NOW, decrypt when quantum arrives. |

**CNSA 2.0** (NSA mandate) requires complete migration to post-quantum cryptography by **2033-2035**.

**pqscan finds every quantum-vulnerable algorithm in your infrastructure.**

---

## ⚡ Quick Start

### Install

```bash
# Build from source
git clone https://github.com/Hacker21-punk/pqscan.git
cd pqscan
go build -o pqscan .

# Or install directly
go install github.com/Hacker21-punk/pqscan@latest
