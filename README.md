# PQScan — Post-Quantum Vulnerability Scanner

**Find it before the quantum computer does.**

PQScan discovers quantum-vulnerable cryptography across your
infrastructure and generates CISO-ready audit reports with a
single command.

## Why This Matters Now

- NIST FIPS 203/204/205 finalized (Aug 2024)
- NSA CNSA 2.0 mandates PQC by 2033
- "Harvest Now, Decrypt Later" attacks are happening TODAY
- Your auditors WILL ask about this in 2026

## Quick Start

```bash
go install github.com/Hacker21-punk/pqscan@latest

# Basic scan
pqscan google.com

# Full CISO audit report (PDF)
pqscan --audit google.com

# Machine-readable CBOM
pqscan --format cbom -o inventory.json google.com<img width="647" height="907" alt="{D9D27832-29B4-48B0-AFA4-839997789347}" src="https://github.com/user-attachments/assets/c98399ad-f709-4c3d-9640-c8c20502c357" />
[google.com-audit-report.pdf](https://github.com/user-attachments/files/26346939/google.com-audit-report.pdf)
[microsoft.com-audit-report.pdf](https://github.com/user-attachments/files/26346938/microsoft.com-audit-report.pdf)
[amazon.com-audit-report.pdf](https://github.com/user-attachments/files/26346937/amazon.com-audit-report.pdf)
[cloudflare.com-audit-report.pdf](https://github.com/user-attachments/files/26346936/cloudflare.com-audit-report.pdf)
[github.com-audit-report.pdf](https://github.com/user-attachments/files/26346933/github.com-audit-report.pdf)
[stripe.com-audit-report.pdf](https://github.com/user-attachments/files/26346931/stripe.com-audit-report.pdf)
[salesforce.com-audit-report.pdf](https://github.com/user-attachments/files/26346930/salesforce.com-audit-report.pdf)
[jpmorgan.com-audit-report.pdf](https://github.com/user-attachments/files/26346929/jpmorgan.com-audit-report.pdf)
[wellsfargo.com-audit-report.pdf](https://github.com/user-attachments/files/26346928/wellsfargo.com-audit-report.pdf)
