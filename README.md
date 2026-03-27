# pqscan

**Post-Quantum Cryptography Vulnerability Scanner**

> Find your quantum-vulnerable encryption before a quantum computer does.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go)](https://go.dev)

---

## What is this?

`pqscan` is an open-source security tool that scans your infrastructure 
and identifies every cryptographic algorithm that will be **broken by 
quantum computers**.

It checks TLS, SSH, STARTTLS (SMTP, IMAP, POP3), certificates, and 
more — then produces actionable reports with risk scores and 
CNSA 2.0 compliance status.

### The Problem

- **94%+ of internet endpoints** use encryption that quantum computers will break
- **"Harvest Now, Decrypt Later"** — adversaries are recording encrypted traffic TODAY, waiting for quantum computers to decrypt it
- **CNSA 2.0** (NSA mandate) requires complete migration to post-quantum cryptography by 2033-2035
- **You can't migrate what you can't find**

`pqscan` finds it.

---

## Quick Start

### Install

```bash
# Build from source
git clone https://github.com/YOUR_USERNAME/pqscan.git
cd pqscan
go build -o pqscan ./cmd/pqscan/

# Or install directly
go install github.com/YOUR_USERNAME/pqscan/cmd/pqscan@latest
