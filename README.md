# ⛓ NullBlock

> **Immutable Threat Intelligence Ledger**  
> A custom blockchain for logging cybersecurity threats — tamper-proof, verifiable, permanent.

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat&logo=python&logoColor=white)
![Blockchain](https://img.shields.io/badge/Blockchain-Custom%20SHA--256-ff3c3c?style=flat)
![Storage](https://img.shields.io/badge/Storage-JSON%20%7C%20localStorage-ff7b00?style=flat)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat)

---

## 📌 What is NullBlock?

NullBlock is a **custom blockchain implementation** built for cybersecurity use cases. Every threat record — whether a malicious IP address, an attack event, or a malware signature — is stored as an **immutable block** on a chain. Once written, it cannot be altered without breaking the entire chain, which is immediately detected by the validator.

This is the exact principle behind why blockchain is powerful for security: **tamper-evidence**. If anyone modifies a historical record, the SHA-256 hash chain breaks and the corruption is provable.

### What gets logged?
- **Network Threats** — Source IPs, attack types (SQL Injection, DDoS, XSS...), severity levels, ports, protocols
- **Malware Signatures** — File hashes, malware names, families (Ransomware, Trojan, Botnet...), hash types

### Two interfaces:
- **Python CLI** — Terminal-based, stores chain as `nullblock_chain.json`
- **Web UI** — Browser-based explorer, stores chain in `localStorage`, fully offline

---

## 📁 Project Structure

```
NullBlock/
├── nullblock.html         # Web UI (open in any browser)
├── nullblock_cli.py       # Python CLI tool
├── nullblock_chain.json   # Chain data file (auto-created by CLI)
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- pip

### Install dependency

```bash
pip install colorama
```

> `colorama` is only for colored terminal output on Windows. The tool works without it.

---

## 💻 CLI Usage
 
### 1. Register a Threat Analyst (Generates RSA Keypair)
 
Before logging threats, you must register an analyst. This creates a secure 2048-bit RSA keypair under `analysts/<name>/` used to sign blocks.
 
```bash
python nullblock_cli.py register-analyst --name "Alice"
```
 
---
 
### 2. Log a Network Threat (Signed by Analyst)
 
Every block must be signed by a registered analyst. Use the analyst's registered name in `--reporter`.
 
```bash
python nullblock_cli.py add-threat \
  --ip 192.168.1.105 \
  --type "SQL Injection" \
  --severity HIGH \
  --port 3306 \
  --protocol TCP \
  --reporter "Alice" \
  --notes "Repeated attempts on MySQL port"
```
 
Severity levels: `LOW` | `MEDIUM` | `HIGH` | `CRITICAL`
 
---
 
### 3. Log a Malware Signature (Signed by Analyst)
 
```bash
python nullblock_cli.py add-malware \
  --hash "5f4dcc3b5aa765d61d8327deb882cf99abc12345" \
  --name "WannaCry" \
  --family "Ransomware" \
  --severity CRITICAL \
  --reporter "Alice" \
  --notes "Exploits EternalBlue (MS17-010)"
```
 
---
 
### 4. View Full Blockchain
 
```bash
python nullblock_cli.py chain
```
 
---
 
### 5. Validate Chain Integrity (Verifies Signatures)
 
```bash
python nullblock_cli.py validate
```
 
> [+] Returns `Chain integrity verified` if all hashes, links, and digital signatures are valid  
> [-] Returns `CHAIN COMPROMISED` if any block is tampered with, signature is forged, or public key is missing
 
---
 
### 6. Search the Ledger
 
```bash
# Search by IP
python nullblock_cli.py search --ip 192.168.1.105
 
# Search by malware name
python nullblock_cli.py search --name WannaCry
 
# Search by hash prefix
python nullblock_cli.py search --hash 5f4dcc
```
 
---
 
### 7. Threat Statistics
 
```bash
python nullblock_cli.py stats
```
 
---
 
## 🌐 Web UI Usage
 
1. Open `nullblock.html` in any browser — no internet required
2. **ANALYSTS** — register new threat analysts, generating native RSA-PSS keypairs using Web Crypto API (stored in browser `localStorage`)
3. **LOG THREAT** — select an analyst, fill in IP, attack type, severity → Commit & Sign to Chain
4. **LOG MALWARE** — select an analyst, fill in hash, name, family → Commit & Sign to Chain
5. **CHAIN** — full blockchain explorer, showing the index, type, timestamps, SHA-256 SPKI public key fingerprints, and base64 signatures
6. **VALIDATE** — verify hashes, block links, and RSA signatures of all blocks in-browser
7. **STATS** — visual breakdown of threat data
8. **SEARCH** — search by IP, malware name, or hash prefix
9. **EXPORT JSON** — download the entire chain as a JSON file
 
---

## ⛓ How the Blockchain Works

### Block Structure

```json
{
  "index": 3,
  "timestamp": "2025-01-15T10:23:45.123456",
  "type": "THREAT",
  "data": {
    "ip_address": "192.168.1.105",
    "attack_type": "SQL Injection",
    "severity": "HIGH",
    "port": "3306",
    "protocol": "TCP",
    "reporter": "SOC-Team",
    "notes": "Repeated attempts on MySQL port"
  },
  "previous_hash": "a3f2c1d9e8b7...",
  "nonce": 0,
  "hash": "7b9e2f1a4c8d..."
}
```

| Field | Purpose |
|-------|---------|
| `index` | Block position in the chain |
| `timestamp` | UTC time of logging |
| `type` | `GENESIS`, `THREAT`, or `MALWARE` |
| `data` | The actual threat intelligence payload |
| `previous_hash` | SHA-256 hash of the block before this one |
| `nonce` | Reserved for future proof-of-work |
| `hash` | SHA-256 hash of this entire block |

---

### The Hash Chain — Why It's Immutable

```
GENESIS BLOCK           BLOCK #1                BLOCK #2
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│ index: 0        │     │ index: 1        │     │ index: 2        │
│ type: GENESIS   │     │ type: THREAT    │     │ type: MALWARE   │
│ prev: 000...000 │     │ prev: ══════════╪═════╪► a3f2c1...     │
│ hash: a3f2c1... │─────► previous_hash  │     │ prev: 7b9e2f... │
└─────────────────┘     │ hash: 7b9e2f...│─────► hash: 9c1a4e...│
                        └─────────────────┘     └─────────────────┘
```

Each block's hash is computed from ALL its contents including the `previous_hash`. This means:

- Change Block #1's data → its hash changes
- Block #2's `previous_hash` no longer matches → invalid
- Every block after is also invalid
- Validator catches this instantly

**You cannot silently edit history.**

---

### Hash Computation

```python
def compute_hash(block):
    block_copy = {k: v for k, v in block.items() if k != "hash"}
    block_string = json.dumps(block_copy, sort_keys=True)
    return hashlib.sha256(block_string.encode()).hexdigest()
```

Block serialized to JSON with sorted keys (determinism) → SHA-256 hashed. The `hash` field is excluded to avoid circular dependency.

---

### Chain Validation Algorithm

```python
for i in range(1, len(chain)):
    current = chain[i]
    previous = chain[i - 1]

    # Check 1: Does this block's hash match its contents?
    if current["hash"] != compute_hash(current):
        return False, f"Block #{i} hash is CORRUPTED"

    # Check 2: Does it correctly link to the previous block?
    if current["previous_hash"] != previous["hash"]:
        return False, f"Block #{i} is DETACHED from chain"
```

Two checks per block. O(n) time. Catches both content tampering and chain relinking attacks.

---

## 🛡️ Cybersecurity Concepts Covered

| Concept | How NullBlock Uses It |
|---------|----------------------|
| **Immutability** | SHA-256 hash chain — any edit breaks all subsequent blocks |
| **Tamper Evidence** | Validator detects and pinpoints exact corrupted block |
| **Cryptographic Hashing** | SHA-256 produces a fixed 256-bit fingerprint of each block |
| **Chain of Custody** | Every record has timestamp, reporter, and cryptographic proof |
| **Threat Intelligence** | Structured logging of IPs, attack types, malware hashes |
| **IOC (Indicators of Compromise)** | Malware hashes and malicious IPs are classic IOC formats |
| **Audit Trail** | Genesis block anchors a complete, verifiable history |
| **Data Integrity** | Sorting keys before hashing ensures deterministic hashes |

---

## 🔗 Real-World Parallels

- **MITRE ATT&CK** — globally shared threat intelligence framework
- **VirusTotal** — crowdsourced malware hash database
- **Blockchain-based PKI** — immutability preventing certificate fraud
- **SIEM audit logs** — tamper-evident security event logs in enterprise SOCs
- **Ethereum event logs** — smart contract events stored immutably on-chain

NullBlock demonstrates the **core principle** behind all of these: once written to the chain, data cannot be quietly changed.

---

## ⚠️ Notes

- Web UI stores data in `localStorage` — use **Export JSON** to back up before clearing browser data
- CLI stores chain in `nullblock_chain.json` — back this file up
- This is a **simplified blockchain** — no P2P network, no consensus, no proof-of-work mining
- For production threat intel, look into **STIX/TAXII** format and platforms like **OpenCTI** or **MISP**

---

## 👤 Author

Built by **[H8RSH100](https://github.com/H8rsh100)** — CS/IT Engineering Student  
Part of a cybersecurity portfolio series alongside **[VaultCipher](https://github.com/H8rsh100/VaultCipher)**.

---

## 📄 License

MIT License — free to use, modify, and learn from.
