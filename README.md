# ECC vs RSA Blind Signatures Benchmark

This repository contains the Python implementation and performance benchmarking of blind signature protocols. It was developed as a practical part of a scientific research paper for the Department of Information Security at Lviv Polytechnic National University (LPNU).

## Overview
The ECC implementation is based on an adapted version of the Jeng et al. blind signature scheme.
The provided script (`ecc_rsa_blind_signature.py`) conducts a comparative analysis of:
1. **ECC Blind Signature**: Implementation of the Jeng et al. scheme using standard NIST curves (P-256, P-384, P-521).
2. **RSA Blind Signature**: Classic Chaum blind signature scheme evaluated at equivalent security levels (3072-bit, 7680-bit, and 15360-bit keys).

## Requirements
To run the benchmarks, you need Python 3.8+ and the following libraries:
- `ecpy`
- `cryptography`

## Installation
You can install the required dependencies using pip:

```bash
pip install ecpy cryptography
```

## Usage
Execute the main script to run the blinding, signing, and unblinding phases for both algorithms. The script will output the average execution times and standard deviations in milliseconds.

```bash
python ecc_rsa_blind_signature.py
```
## Reproducibility
All experiments can be reproduced by running the provided script with default parameters.
## Author
**Khrystyna Kuchma** — Student at the Department of Information Security, Group KB-101, LPNU.
