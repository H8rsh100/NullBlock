#!/usr/bin/env python3
"""
NullBlock CLI — Immutable Threat Intelligence Ledger
A custom blockchain for logging cybersecurity threats.
 
Requirements:
    pip install colorama
 
Usage:
    python nullblock_cli.py add-threat   --ip 192.168.1.1 --type "SQL Injection" --severity HIGH
    python nullblock_cli.py add-malware  --hash "abc123..." --name "WannaCry" --family Ransomware
    python nullblock_cli.py chain        # view full blockchain
    python nullblock_cli.py validate     # verify chain integrity
    python nullblock_cli.py search       --ip 192.168.1.1
    python nullblock_cli.py stats        # threat statistics
"""
 
import json
import hashlib
import time
import argparse
import os
import base64
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
 
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    C = True
except ImportError:
    class Fore:
        GREEN = RED = YELLOW = CYAN = MAGENTA = WHITE = ""
    class Style:
        BRIGHT = RESET_ALL = DIM = ""
    C = False
 
CHAIN_FILE = "nullblock_chain.json"
 
BANNER = f"""
{Fore.CYAN}{Style.BRIGHT}
███╗   ██╗██╗   ██╗██╗     ██╗     ██████╗ ██╗      ██████╗  ██████╗██╗  ██╗
████╗  ██║██║   ██║██║     ██║     ██╔══██╗██║     ██╔═══██╗██╔════╝██║ ██╔╝
██╔██╗ ██║██║   ██║██║     ██║     ██████╔╝██║     ██║   ██║██║     █████╔╝
██║╚██╗██║██║   ██║██║     ██║     ██╔══██╗██║     ██║   ██║██║     ██╔═██╗
██║ ╚████║╚██████╔╝███████╗███████╗██████╔╝███████╗╚██████╔╝╚██████╗██║  ██╗
╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝
{Style.RESET_ALL}{Fore.WHITE}         Immutable Threat Intelligence Ledger  |  Powered by Blockchain{Style.RESET_ALL}
"""
 
 
# ─────────────────────────────────────────
# Block & Chain Core
# ─────────────────────────────────────────
 
def compute_hash(block: dict) -> str:
    """SHA-256 hash of block contents (excluding 'hash' and 'signature' fields)."""
    block_copy = {k: v for k, v in block.items() if k not in ("hash", "signature")}
    block_string = json.dumps(block_copy, sort_keys=True)
    return hashlib.sha256(block_string.encode()).hexdigest()
 
 
def create_genesis_block() -> dict:
    """The first block — hardcoded, anchors the chain."""
    block = {
        "index": 0,
        "timestamp": "2024-01-01T00:00:00",
        "type": "GENESIS",
        "data": {"message": "NullBlock Genesis — Threat Intelligence Ledger Initialized"},
        "previous_hash": "0" * 64,
        "nonce": 0,
    }
    block["hash"] = compute_hash(block)
    return block
 
 
def load_chain() -> list:
    """Load chain from disk, or initialize with genesis block."""
    if os.path.exists(CHAIN_FILE):
        with open(CHAIN_FILE, "r") as f:
            return json.load(f)
    chain = [create_genesis_block()]
    save_chain(chain)
    return chain
 
 
def save_chain(chain: list):
    """Persist chain to disk."""
    with open(CHAIN_FILE, "w") as f:
        json.dump(chain, f, indent=2)
 
 
def register_analyst(name: str, key_size: int = 2048):
    """Generate RSA keypair for an analyst and save PEM files."""
    analyst_dir = os.path.join("analysts", name)
    os.makedirs(analyst_dir, exist_ok=True)
    
    priv_path = os.path.join(analyst_dir, "private_key.pem")
    pub_path = os.path.join(analyst_dir, "public_key.pem")
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
        
    with open(pub_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        
    # Ensure analysts/ is in .gitignore
    gitignore_path = ".gitignore"
    add_to_gitignore = True
    if os.path.exists(gitignore_path):
        with open(gitignore_path, "r") as f:
            content = f.read()
            if "analysts/" in content:
                add_to_gitignore = False
    if add_to_gitignore:
        with open(gitignore_path, "a") as f:
            f.write("\nanalysts/\n")
            
    # Public key fingerprint
    pub_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    fingerprint = "SHA256:" + hashlib.sha256(pub_der).hexdigest()
    
    return priv_path, pub_path, fingerprint
 
 
def add_block(data: dict, block_type: str, reporter: str) -> dict:
    """Add a new block to the chain signed by the reporter."""
    chain = load_chain()
    previous_block = chain[-1]
    
    key_path = os.path.join("analysts", reporter, "private_key.pem")
    if not os.path.exists(key_path):
        raise FileNotFoundError(f"Reporter '{reporter}' key pair not found. Register them first using 'register-analyst'.")
        
    with open(key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        
    public_key = private_key.public_key()
    pub_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    fingerprint = "SHA256:" + hashlib.sha256(pub_der).hexdigest()
    
    block = {
        "index": len(chain),
        "timestamp": datetime.utcnow().isoformat(),
        "type": block_type,
        "data": data,
        "previous_hash": previous_block["hash"],
        "nonce": 0,
        "reporter": reporter,
        "reporter_fingerprint": fingerprint
    }
    
    block["hash"] = compute_hash(block)
    
    signature = private_key.sign(
        block["hash"].encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    block["signature"] = base64.b64encode(signature).decode()
    
    chain.append(block)
    save_chain(chain)
    return block
 
 
def validate_chain(chain: list) -> tuple:
    """
    Validate entire chain integrity, including signatures.
    Returns (is_valid: bool, error_message: str)
    """
    for i in range(1, len(chain)):
        current = chain[i]
        previous = chain[i - 1]
 
        # Check hash integrity
        expected_hash = compute_hash(current)
        if current["hash"] != expected_hash:
            return False, f"Block #{i} hash is CORRUPTED"
 
        # Check linkage
        if current["previous_hash"] != previous["hash"]:
            return False, f"Block #{i} is DETACHED from chain (previous_hash mismatch)"
            
        # Verify RSA signature (required for all non-genesis blocks)
        if current["type"] != "GENESIS":
            if "signature" not in current:
                return False, f"Block #{i} signature is missing (unsigned block)"
                
            reporter = current.get("reporter")
            if not reporter:
                return False, f"Block #{i} reporter is missing"
                
            pub_key_path = os.path.join("analysts", reporter, "public_key.pem")
            if not os.path.exists(pub_key_path):
                return False, f"Block #{i} signature verification failed (Public key for reporter '{reporter}' not found)"
                
            try:
                with open(pub_key_path, "rb") as f:
                    public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
                sig_bytes = base64.b64decode(current["signature"].encode())
                public_key.verify(
                    sig_bytes,
                    current["hash"].encode(),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            except Exception as e:
                return False, f"Block #{i} has an INVALID signature (forgery/corruption detected: {e})"
 
    return True, "Chain integrity verified — all hashes, links, and signatures valid"
 
 
# ─────────────────────────────────────────
# CLI Commands
# ─────────────────────────────────────────
 
def cmd_register_analyst(args):
    try:
        priv_path, pub_path, fingerprint = register_analyst(args.name, args.bits)
        print(f"\n{Fore.GREEN}✅ Analyst '{args.name}' registered successfully!{Style.RESET_ALL}")
        print(f"   Fingerprint: {Fore.CYAN}{fingerprint}{Style.RESET_ALL}")
        print(f"   Private Key: {priv_path}")
        print(f"   Public Key : {pub_path}\n")
    except Exception as e:
        print(f"\n{Fore.RED}❌ Registration failed: {e}{Style.RESET_ALL}\n")
 
 
def cmd_add_threat(args):
    severity_colors = {"LOW": Fore.GREEN, "MEDIUM": Fore.YELLOW, "HIGH": Fore.RED, "CRITICAL": Fore.MAGENTA}
    data = {
        "ip_address": args.ip,
        "attack_type": args.type,
        "severity": args.severity.upper(),
        "port": args.port if args.port else "unknown",
        "protocol": args.protocol if args.protocol else "unknown",
        "notes": args.notes if args.notes else "",
    }
    try:
        block = add_block(data, "THREAT", args.reporter)
        sc = severity_colors.get(data["severity"], Fore.WHITE)
        print(f"\n{Fore.GREEN}✅ Threat logged and signed on NullBlock chain{Style.RESET_ALL}")
        print(f"   Block Index  : {Fore.CYAN}#{block['index']}{Style.RESET_ALL}")
        print(f"   Block Hash   : {Fore.YELLOW}{block['hash'][:32]}...{Style.RESET_ALL}")
        print(f"   Reporter     : {Fore.WHITE}{block['reporter']}{Style.RESET_ALL}")
        print(f"   Fingerprint  : {Fore.WHITE}{block.get('reporter_fingerprint', '')[:24]}...{Style.RESET_ALL}")
        print(f"   Signature    : {Fore.WHITE}{block.get('signature', '')[:24]}...{Style.RESET_ALL}")
        print(f"   IP Address   : {Fore.WHITE}{data['ip_address']}{Style.RESET_ALL}")
        print(f"   Attack Type  : {Fore.WHITE}{data['attack_type']}{Style.RESET_ALL}")
        print(f"   Severity     : {sc}{data['severity']}{Style.RESET_ALL}")
        print(f"   Timestamp    : {Style.DIM}{block['timestamp']}{Style.RESET_ALL}\n")
    except Exception as e:
        print(f"\n{Fore.RED}❌ Failed to log threat: {e}{Style.RESET_ALL}\n")
 
 
def cmd_add_malware(args):
    data = {
        "hash": args.hash,
        "name": args.name,
        "family": args.family,
        "hash_type": args.hash_type if args.hash_type else "SHA256",
        "severity": args.severity.upper() if args.severity else "HIGH",
        "notes": args.notes if args.notes else "",
    }
    try:
        block = add_block(data, "MALWARE", args.reporter)
        print(f"\n{Fore.GREEN}✅ Malware signature logged and signed on NullBlock chain{Style.RESET_ALL}")
        print(f"   Block Index  : {Fore.CYAN}#{block['index']}{Style.RESET_ALL}")
        print(f"   Block Hash   : {Fore.YELLOW}{block['hash'][:32]}...{Style.RESET_ALL}")
        print(f"   Reporter     : {Fore.WHITE}{block['reporter']}{Style.RESET_ALL}")
        print(f"   Fingerprint  : {Fore.WHITE}{block.get('reporter_fingerprint', '')[:24]}...{Style.RESET_ALL}")
        print(f"   Signature    : {Fore.WHITE}{block.get('signature', '')[:24]}...{Style.RESET_ALL}")
        print(f"   Malware Name : {Fore.RED}{data['name']}{Style.RESET_ALL}")
        print(f"   Family       : {Fore.WHITE}{data['family']}{Style.RESET_ALL}")
        print(f"   File Hash    : {Style.DIM}{data['hash'][:32]}...{Style.RESET_ALL}")
        print(f"   Timestamp    : {Style.DIM}{block['timestamp']}{Style.RESET_ALL}\n")
    except Exception as e:
        print(f"\n{Fore.RED}❌ Failed to log malware: {e}{Style.RESET_ALL}\n")
 
 
def cmd_chain(args):
    chain = load_chain()
    print(f"\n{Fore.CYAN}{Style.BRIGHT}⛓  NullBlock Chain — {len(chain)} blocks{Style.RESET_ALL}\n")
    for block in chain:
        t = block["type"]
        color = Fore.CYAN if t == "GENESIS" else Fore.RED if t == "THREAT" else Fore.MAGENTA
        print(f"  {color}[{t}]{Style.RESET_ALL} Block #{block['index']}  |  {Style.DIM}{block['timestamp']}{Style.RESET_ALL}")
        print(f"  Hash         : {Fore.YELLOW}{block['hash'][:48]}...{Style.RESET_ALL}")
        print(f"  Prev Hash    : {Style.DIM}{block['previous_hash'][:48]}...{Style.RESET_ALL}")
        if t != "GENESIS":
            print(f"  Reporter     : {Fore.WHITE}{block.get('reporter')} (Fingerprint: {block.get('reporter_fingerprint', '')[:16]}...){Style.RESET_ALL}")
            print(f"  Signature    : {Style.DIM}{block.get('signature', '')[:48]}...{Style.RESET_ALL}")
        if t == "THREAT":
            d = block["data"]
            print(f"  IP           : {d.get('ip_address')}  |  Attack: {d.get('attack_type')}  |  Severity: {d.get('severity')}")
        elif t == "MALWARE":
            d = block["data"]
            print(f"  Malware      : {d.get('name')}  |  Family: {d.get('family')}  |  Hash: {d.get('hash','')[:24]}...")
        print(f"  {'─'*70}")
    print()
 
 
def cmd_validate(args):
    chain = load_chain()
    print(f"\n{Fore.CYAN}🔍 Validating NullBlock chain ({len(chain)} blocks)...{Style.RESET_ALL}")
    is_valid, message = validate_chain(chain)
    if is_valid:
        print(f"{Fore.GREEN}✅ {message}{Style.RESET_ALL}\n")
    else:
        print(f"{Fore.RED}❌ CHAIN COMPROMISED: {message}{Style.RESET_ALL}\n")
 
 
def cmd_search(args):
    chain = load_chain()
    results = []
    for block in chain:
        d = block.get("data", {})
        if args.ip and d.get("ip_address") == args.ip:
            results.append(block)
        elif args.hash and d.get("hash", "").startswith(args.hash):
            results.append(block)
        elif args.name and args.name.lower() in d.get("name", "").lower():
            results.append(block)
 
    if not results:
        print(f"\n{Fore.YELLOW}⚠  No matching records found.{Style.RESET_ALL}\n")
        return
 
    print(f"\n{Fore.CYAN}🔎 Found {len(results)} record(s):{Style.RESET_ALL}\n")
    for block in results:
        print(f"  Block #{block['index']}  |  {block['type']}  |  {block['timestamp']}")
        print(f"  Hash   : {Fore.YELLOW}{block['hash'][:48]}...{Style.RESET_ALL}")
        if block.get("type") != "GENESIS":
            print(f"  Reporter: {block.get('reporter')} | Fingerprint: {block.get('reporter_fingerprint','')[:24]}...")
        print(f"  Data   : {json.dumps(block['data'], indent=9)}")
        print()
 
 
def cmd_stats(args):
    chain = load_chain()
    threats = [b for b in chain if b["type"] == "THREAT"]
    malware = [b for b in chain if b["type"] == "MALWARE"]
    severities = {}
    attack_types = {}
    families = {}
 
    for b in threats:
        s = b["data"].get("severity", "UNKNOWN")
        severities[s] = severities.get(s, 0) + 1
        a = b["data"].get("attack_type", "UNKNOWN")
        attack_types[a] = attack_types.get(a, 0) + 1
 
    for b in malware:
        f = b["data"].get("family", "UNKNOWN")
        families[f] = families.get(f, 0) + 1
 
    print(f"\n{Fore.CYAN}{Style.BRIGHT}📊 NullBlock Statistics{Style.RESET_ALL}")
    print(f"   Total Blocks     : {Fore.WHITE}{len(chain)}{Style.RESET_ALL}")
    print(f"   Threat Records   : {Fore.RED}{len(threats)}{Style.RESET_ALL}")
    print(f"   Malware Records  : {Fore.MAGENTA}{len(malware)}{Style.RESET_ALL}")
    if severities:
        print(f"\n   {Fore.YELLOW}Severity Breakdown:{Style.RESET_ALL}")
        for s, count in sorted(severities.items()):
            print(f"     {s:<10} : {count}")
    if attack_types:
        print(f"\n   {Fore.YELLOW}Top Attack Types:{Style.RESET_ALL}")
        for a, count in sorted(attack_types.items(), key=lambda x: -x[1])[:5]:
            print(f"     {a:<20} : {count}")
    if families:
        print(f"\n   {Fore.YELLOW}Malware Families:{Style.RESET_ALL}")
        for f, count in sorted(families.items(), key=lambda x: -x[1]):
            print(f"     {f:<20} : {count}")
    print()
 
 
# ─────────────────────────────────────────
# Main
# ─────────────────────────────────────────
 
def main():
    print(BANNER)
    parser = argparse.ArgumentParser(
        prog="nullblock",
        description="NullBlock — Immutable Threat Intelligence Ledger"
    )
    sub = parser.add_subparsers(dest="command", required=True)
 
    # register-analyst
    p_reg = sub.add_parser("register-analyst", help="Register a threat analyst (generates RSA keypair)")
    p_reg.add_argument("--name", required=True, help="Analyst name / identity")
    p_reg.add_argument("--bits", type=int, default=2048, choices=[2048, 4096], help="RSA key size (default: 2048)")
    p_reg.set_defaults(func=cmd_register_analyst)
 
    # add-threat
    p1 = sub.add_parser("add-threat", help="Log a network threat to the chain")
    p1.add_argument("--ip", required=True, help="Source IP address")
    p1.add_argument("--type", required=True, help="Attack type (e.g. 'SQL Injection')")
    p1.add_argument("--severity", required=True, choices=["LOW","MEDIUM","HIGH","CRITICAL"], help="Threat severity")
    p1.add_argument("--port", help="Target port")
    p1.add_argument("--protocol", help="Protocol (TCP/UDP)")
    p1.add_argument("--notes", help="Additional notes")
    p1.add_argument("--reporter", required=True, help="Reporter identity (must be registered)")
    p1.set_defaults(func=cmd_add_threat)
 
    # add-malware
    p2 = sub.add_parser("add-malware", help="Log a malware signature to the chain")
    p2.add_argument("--hash", required=True, help="File hash (SHA256 recommended)")
    p2.add_argument("--name", required=True, help="Malware name")
    p2.add_argument("--family", required=True, help="Malware family (e.g. Ransomware, Trojan)")
    p2.add_argument("--hash-type", help="Hash type (default: SHA256)")
    p2.add_argument("--severity", help="Severity level")
    p2.add_argument("--notes", help="Additional notes")
    p2.add_argument("--reporter", required=True, help="Reporter identity (must be registered)")
    p2.set_defaults(func=cmd_add_malware)
 
    # chain
    p3 = sub.add_parser("chain", help="Display full blockchain")
    p3.set_defaults(func=cmd_chain)
 
    # validate
    p4 = sub.add_parser("validate", help="Verify chain integrity")
    p4.set_defaults(func=cmd_validate)
 
    # search
    p5 = sub.add_parser("search", help="Search the ledger")
    p5.add_argument("--ip", help="Search by IP address")
    p5.add_argument("--hash", help="Search by malware hash prefix")
    p5.add_argument("--name", help="Search by malware name")
    p5.set_defaults(func=cmd_search)
 
    # stats
    p6 = sub.add_parser("stats", help="Threat statistics")
    p6.set_defaults(func=cmd_stats)
 
    args = parser.parse_args()
    args.func(args)
 
 
if __name__ == "__main__":
    main()