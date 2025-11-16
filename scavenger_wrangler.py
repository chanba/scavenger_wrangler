#!/usr/bin/env python3
"""
scavenger-wrangler.py

Slim Scavenger consolidator for Midnight / Cardano.

Overview
--------
This tool derives or imports donor addresses, signs a CIP-8 message
assigning Scavenger rights to a destination address, and calls the
Scavenger API /donate_to/<dest>/<original>/<signature>.

It supports three main modes:

  1) Normal consolidation:
       donor -> DESTINATION_ADDR

  2) Unassign / undo consolidation:
       donor -> donor   (self-assignment per index; use --unassign)

  3) Derive-only:
       just derive addresses and write them out; no signing, no API calls.

Inputs
------
You can supply donors from:
  1) CSV
  2) On-the-fly derivation
  3) Both combined (rows are processed in the order: CSV, then derived)

1) CSV format (header required):
   index,external,address
   0,1,addr1q...
   1,1,addr1q...
   - "external" column is ignored; ROLE=0 (external) is assumed.

2) Derivation (CIP-1852):
   --numaddresses N   (derive N addresses on ROLE=0)
   --account 0        (CIP-1852 account index, default 0)
   --network-tag mainnet | testnet

Derivation path (CIP-1852):
  m / 1852' / 1815' / ACCOUNT' / ROLE / INDEX
with ROLE fixed to 0 (external) in this tool.

CIP-8 message:
  "Assign accumulated Scavenger rights to: <DESTINATION_ADDRESS>"

Each donor signs the message with cardano-signer, then we POST:
  /donate_to/<dest>/<original>/<signature>

Flags
-----
--unassign
    Undo consolidation by assigning each donor address to itself
    (destination = donor address per row). --destination-addr is ignored.

--derive-address-only
    Derive addresses only; no signing and no API calls.

Outputs (per run folder)
------------------------
Full (consolidation / unassign) mode:
- log.jsonl           : detailed JSON per donor (DonationResult)
- summary.csv         : one row per donor
- signatures.csv      : (index, path, address, destination, signature_hex)
- job_summary.txt     : human-readable summary

Derive-only mode (--derive-address-only):
- derived_addresses.txt : addresses, one per line
- derived_addresses.csv : (index, path, address)
- job_summary.txt       : derivation summary

Requirements
------------
- Python 3.8+
- pip install requests
- cardano-signer in PATH
- If using --numaddresses or --derive-address-only: cardano-address in PATH

Security note
-------------
Passing mnemonics on the CLI can expose them in shell history and process
lists. Use with caution.
"""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional, Sequence, Tuple, Dict

import requests


DONATE_MESSAGE_PREFIX = "Assign accumulated Scavenger rights to: "
DEFAULT_UA = "curl/8.16.0"
DEFAULT_API_URL = "https://scavenger.prod.gd.midnighttge.io"


# ------------------------ data types ------------------------

@dataclass
class DonorRow:
    line_no: int
    index: int
    role: int   # always 0 in this tool
    path: str   # 1852H/1815H/{acct}H/{role}/{index}
    address: str


@dataclass
class DonationResult:
    line_no: int
    index: int
    role: int
    path: str
    address: str
    destination: str
    http_code: int
    status_class: str      # success | already_assigned | not_registered | client_error | server_error | rate_limited | network_error | other | dry_run | sign_error
    donation_id: Optional[str]
    solutions_consolidated: Optional[int]
    signature_hex: Optional[str]
    response_raw: str


# ------------------------ helpers ------------------------

def ensure_binary(name: str) -> None:
    """Exit with error if a required binary is not on PATH."""
    if shutil.which(name) is None:
        print(f"ERROR: required binary not found on PATH: {name}", file=sys.stderr)
        sys.exit(1)


def run(cmd: Sequence[str], *, input_text: Optional[str] = None, timeout: Optional[int] = None) -> subprocess.CompletedProcess:
    """Run a command, capturing stdout/stderr."""
    try:
        return subprocess.run(
            list(cmd),
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )
    except OSError as e:
        raise RuntimeError(f"Failed to execute {' '.join(cmd)}: {e}") from e


def json_parse_maybe_trailing(stdout: str) -> dict:
    """Parse JSON, allowing extra non-JSON noise before the last object."""
    s = stdout.strip()
    if not s:
        raise ValueError("No output to parse as JSON")
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        last = s.rfind("{")
        if last != -1:
            cand = s[last:]
            try:
                return json.loads(cand)
            except json.JSONDecodeError:
                pass
        raise


def classify_status(http_code: int, *, is_network_error: bool = False) -> str:
    """Map HTTP status codes (and network failures) to status classes."""
    if is_network_error:
        return "network_error"
    if http_code == 200:
        return "success"
    if http_code == 409:
        return "already_assigned"
    if http_code == 404:
        return "not_registered"
    if http_code == 429:
        return "rate_limited"
    if 400 <= http_code < 500:
        return "client_error"
    if 500 <= http_code < 600:
        return "server_error"
    return "other"


def human_bucket(status_class: str, dry_run: bool, from_addr: str, to_addr: str) -> str:
    """
    Bucket results for summary:
      assigned   : success OR already_assigned (unless from==to in success -> unassigned)
      unassigned : success AND from==to (donate back to self) OR dry-run non-errors
      failed     : sign_error, network_error, client_error, server_error,
                   not_registered, rate_limited, other
    """
    if status_class in {"sign_error", "network_error"}:
        return "failed"

    if dry_run:
        # In dry-run we don't change assignments, but distinguish hard failures above.
        return "unassigned"

    if status_class == "success":
        if from_addr == to_addr:
            return "unassigned"
        return "assigned"

    if status_class == "already_assigned":
        return "assigned"

    return "failed"


def validate_mnemonic(mnemonic: str) -> None:
    """Basic mnemonic validation: word count typical for BIP-style seeds."""
    words = mnemonic.strip().split()
    if len(words) not in {12, 15, 18, 21, 24}:
        print(f"WARNING: mnemonic has {len(words)} words (expected 12/15/18/21/24).", file=sys.stderr)


def validate_destination_address(addr: str, network_tag: str) -> None:
    """Basic destination address sanity checks."""
    addr = addr.strip()
    if not addr:
        print("ERROR: destination address is empty", file=sys.stderr)
        sys.exit(2)
    if len(addr) < 20:
        print("WARNING: destination address looks unusually short", file=sys.stderr)

    # Basic mainnet/testnet consistency checks for bech32-style addrs.
    if network_tag == "mainnet" and addr.startswith("addr_test1"):
        print("ERROR: destination address looks like testnet but --network-tag=mainnet", file=sys.stderr)
        sys.exit(2)
    if network_tag == "testnet" and addr.startswith("addr1"):
        print("ERROR: destination address looks like mainnet but --network-tag=testnet", file=sys.stderr)
        sys.exit(2)


# ------------------------ derivation & signing ------------------------

def derive_addresses_external(mnemonic: str, account: int, n: int, network_tag: str) -> List[DonorRow]:
    """
    Derive the first N external (ROLE=0) base addresses using cardano-address.
    Returns a list of DonorRow with index, role=0, path, and address.
    """
    ensure_binary("cardano-address")

    # root xprv
    proc = run(["cardano-address", "key", "from-recovery-phrase", "Shelley"], input_text=mnemonic)
    if proc.returncode != 0:
        raise RuntimeError(f"cardano-address key from-recovery-phrase failed: {proc.stderr.strip()}")
    root_xprv = proc.stdout.strip()

    # account xprv
    proc = run(["cardano-address", "key", "child", f"1852H/1815H/{account}H"], input_text=root_xprv)
    if proc.returncode != 0:
        raise RuntimeError(f"cardano-address key child account failed: {proc.stderr.strip()}")
    acct_xprv = proc.stdout.strip()

    # stake xpub (2/0)
    proc = run(["cardano-address", "key", "child", "2/0"], input_text=acct_xprv)
    if proc.returncode != 0:
        raise RuntimeError(f"cardano-address key child stake failed: {proc.stderr.strip()}")
    stake_xprv = proc.stdout.strip()

    proc = run(["cardano-address", "key", "public", "--with-chain-code"], input_text=stake_xprv)
    if proc.returncode != 0:
        raise RuntimeError(f"cardano-address key public (stake) failed: {proc.stderr.strip()}")
    stake_xpub = proc.stdout.strip()

    donors: List[DonorRow] = []
    for i in range(n):
        role = 0  # external only
        # payment xprv at role/index
        proc = run(["cardano-address", "key", "child", f"{role}/{i}"], input_text=acct_xprv)
        if proc.returncode != 0:
            raise RuntimeError(f"cardano-address key child payment {role}/{i} failed: {proc.stderr.strip()}")
        pay_xprv = proc.stdout.strip()

        proc = run(["cardano-address", "key", "public", "--with-chain-code"], input_text=pay_xprv)
        if proc.returncode != 0:
            raise RuntimeError(f"cardano-address key public (payment {i}) failed: {proc.stderr.strip()}")
        pay_xpub = proc.stdout.strip()

        # enterprise payment address
        proc = run(["cardano-address", "address", "payment", "--network-tag", network_tag], input_text=pay_xpub)
        if proc.returncode != 0:
            raise RuntimeError(f"cardano-address address payment failed for index {i}: {proc.stderr.strip()}")
        enterprise_addr = proc.stdout.strip()

        # add delegation to stake_xpub -> base addr1...
        proc = run(["cardano-address", "address", "delegation", stake_xpub], input_text=enterprise_addr)
        if proc.returncode != 0:
            raise RuntimeError(f"cardano-address address delegation failed for index {i}: {proc.stderr.strip()}")
        base_addr = proc.stdout.strip()

        donors.append(DonorRow(
            line_no=-1,
            index=i,
            role=role,
            path=f"1852H/1815H/{account}H/{role}/{i}",
            address=base_addr,
        ))

    return donors


def load_csv(path: Path, account: int) -> List[DonorRow]:
    rows: List[DonorRow] = []
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        required = {"index", "external", "address"}
        if not required.issubset(reader.fieldnames or []):
            raise RuntimeError(f"CSV must have columns: {', '.join(sorted(required))}")
        for line_no, rec in enumerate(reader, start=2):
            idx_s = (rec.get("index") or "").strip()
            addr = (rec.get("address") or "").strip()
            if not idx_s or not addr:
                print(f"WARNING: skipping CSV line {line_no}: missing index or address", file=sys.stderr)
                continue
            try:
                idx = int(idx_s)
            except ValueError:
                print(f"WARNING: skipping CSV line {line_no}: non-integer index '{idx_s}'", file=sys.stderr)
                continue
            role = 0  # ignore CSV "external"; always external in this tool
            rows.append(DonorRow(
                line_no=line_no,
                index=idx,
                role=role,
                path=f"1852H/1815H/{account}H/{role}/{idx}",
                address=addr,
            ))
    return rows


def derive_skey(mnemonic: str, account: int, role: int, index: int, out_dir: Path) -> Path:
    ensure_binary("cardano-signer")
    path = f"1852H/1815H/{account}H/{role}/{index}"
    skey_path = out_dir / "skey.skey"
    cmd = [
        "cardano-signer", "keygen",
        "--mnemonics", mnemonic,
        "--path", path,
        "--json-extended",
        "--out-skey", str(skey_path),
    ]
    proc = run(cmd)
    if proc.returncode != 0:
        raise RuntimeError(f"cardano-signer keygen failed for {path}: {proc.stderr.strip()}")
    if not skey_path.exists():
        raise RuntimeError("cardano-signer keygen reported success but skey file missing")
    return skey_path


def cip8_sign(skey_path: Path, original_addr: str, dest_addr: str) -> Tuple[str, str]:
    message = f"{DONATE_MESSAGE_PREFIX}{dest_addr}"
    cmd = [
        "cardano-signer", "sign",
        "--cip8",
        "--data", message,
        "--secret-key", str(skey_path),
        "--address", original_addr,
        "--json-extended",
    ]
    proc = run(cmd)
    if proc.returncode != 0:
        raise RuntimeError(f"cardano-signer sign failed: {proc.stderr.strip() or proc.stdout.strip()}")
    data = json_parse_maybe_trailing(proc.stdout)
    output = data.get("output") or {}
    sig_hex = output.get("COSE_Sign1_hex")
    pubkey_hex = data.get("publicKey")
    if not isinstance(sig_hex, str):
        raise RuntimeError("Missing output.COSE_Sign1_hex in signer output")
    if not isinstance(pubkey_hex, str):
        raise RuntimeError("Missing publicKey in signer output")
    int(sig_hex, 16)
    int(pubkey_hex, 16)
    return sig_hex, pubkey_hex


# ------------------------ donate_to ------------------------

def donate_to(api_url: str, dest_addr: str, original_addr: str, sig_hex: str, session: requests.Session, timeout: int = 60) -> requests.Response:
    url = f"{api_url.rstrip('/')}/donate_to/{dest_addr}/{original_addr}/{sig_hex}"
    headers = {"Content-Type": "application/json"}
    return session.post(url, json={}, headers=headers, timeout=timeout)


# ------------------------ main ------------------------

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Scavenger Wrangler: mnemonic + (csv and/or derive) -> donate_to."
    )
    ap.add_argument("--mnemonic", required=True, help="BIP-style mnemonic (quoted)")

    # Derive-only mode
    ap.add_argument(
        "--derive-address-only", action="store_true",
        help="Only derive external addresses (ROLE=0) and write artifacts. No signing, no API calls. Requires --numaddresses."
    )

    ap.add_argument("--destination-addr", help="Recipient addr1... (required unless --unassign or --derive-address-only)")
    ap.add_argument("--unassign", action="store_true",
                    help="Undo consolidation by assigning each donor address to itself (self-assignment per row). "
                         "If set, --destination-addr is ignored.")
    ap.add_argument("--csv", help="CSV with columns: index,external,address (external is ignored)")
    ap.add_argument("--numaddresses", type=int, default=0, help="If >0, derive this many external addresses (ROLE=0)")
    ap.add_argument("--account", type=int, default=0, help="HD account index (default: 0)")
    ap.add_argument("--network-tag", choices=["mainnet", "testnet"], default="mainnet",
                    help="For address derivation with cardano-address (default: mainnet)")

    ap.add_argument("--api-url", default=DEFAULT_API_URL, help="Scavenger API base URL")
    ap.add_argument("--user-agent", default=DEFAULT_UA, help="User-Agent header for HTTP requests")
    ap.add_argument("--per-request-delay", type=float, default=1.0,
                    help="Sleep seconds after each non-429 response (default: 1.0)")
    ap.add_argument("--max429", type=int, default=6, help="Max retries on HTTP 429 per address (default: 6)")
    ap.add_argument("--backoff-base", type=float, default=5.0,
                    help="Base seconds for exponential backoff on 429 (default: 5.0)")
    ap.add_argument("--out-dir", default="consolidate-logs",
                    help="Base output directory; a timestamped run subfolder will be created inside")
    ap.add_argument("--log-file", help="Custom JSONL log path (overrides run-folder log.jsonl)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Generate and log signatures, but DO NOT call the API")

    return ap.parse_args()


def main() -> None:
    args = parse_args()

    mnemonic = " ".join(args.mnemonic.split())
    validate_mnemonic(mnemonic)

    # Prepare base + run folder once
    base_dir = Path(args.out_dir)
    base_dir.mkdir(parents=True, exist_ok=True)
    run_ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    run_dir = base_dir / f"run-{run_ts}"
    run_dir.mkdir(parents=True, exist_ok=True)

    # Derive-only artifact paths
    derived_txt = run_dir / "derived_addresses.txt"
    derived_csv = run_dir / "derived_addresses.csv"
    job_summary_path = run_dir / "job_summary.txt"

    # ---------------- derive-address-only mode ----------------
    if args.derive_address_only:
        if args.numaddresses <= 0:
            print("ERROR: --derive-address-only requires --numaddresses > 0", file=sys.stderr)
            sys.exit(2)

        donors = derive_addresses_external(mnemonic, args.account, args.numaddresses, args.network_tag)

        # Write text + CSV artifacts inside the run folder
        with derived_txt.open("w", encoding="utf-8") as ftxt, derived_csv.open("w", newline="", encoding="utf-8") as fcsv:
            w = csv.writer(fcsv)
            w.writerow(["index", "path", "address"])
            for d in donors:
                ftxt.write(d.address + "\n")
                w.writerow([d.index, d.path, d.address])

        # Derive-only job summary
        lines: List[str] = []
        lines.append("=== Scavenger Derive-Only Job Summary ===")
        lines.append(f"run_folder     : {run_dir.name}")
        lines.append(f"account        : {args.account}")
        lines.append(f"network-tag    : {args.network_tag}")
        lines.append(f"count          : {len(donors)}")
        lines.append("")
        lines.append(f"Derivation: m/1852H/1815H/{args.account}H/0/<index> (external chain)")
        lines.append("Artifacts:")
        lines.append(f"- derived_addresses.txt")
        lines.append(f"- derived_addresses.csv")

        with job_summary_path.open("w", encoding="utf-8") as fsum:
            fsum.write("\n".join(lines))

        # Also print addresses to stdout for convenience
        for d in donors:
            print(d.address)

        print("\nWrote:")
        print(f"  {derived_txt}")
        print(f"  {derived_csv}")
        print(f"  {job_summary_path}")
        return

    # ---------------- consolidation / unassign mode ----------------

    dest_addr: Optional[str] = None
    if args.unassign:
        if args.destination_addr:
            print("WARNING: --destination-addr is ignored when --unassign is set.", file=sys.stderr)
    else:
        if not args.destination_addr:
            print("ERROR: --destination-addr is required unless --unassign or --derive-address-only is used", file=sys.stderr)
            sys.exit(2)
        dest_addr = args.destination_addr.strip()
        validate_destination_address(dest_addr, args.network_tag)

    # Artifact paths (all contained inside this run folder, except custom log-file)
    log_path = Path(args.log_file) if args.log_file else (run_dir / "log.jsonl")
    summary_csv_path = run_dir / "summary.csv"
    signatures_csv_path = run_dir / "signatures.csv"
    job_summary_path = run_dir / "job_summary.txt"

    # Build donor list
    donors: List[DonorRow] = []
    if args.csv:
        donors.extend(load_csv(Path(args.csv), args.account))
    if args.numaddresses > 0:
        donors.extend(derive_addresses_external(mnemonic, args.account, args.numaddresses, args.network_tag))

    if not donors:
        print("Nothing to do: provide --csv and/or --numaddresses", file=sys.stderr)
        sys.exit(1)

    # Check external binaries up front (best effort)
    ensure_binary("cardano-signer")
    if args.numaddresses > 0:
        ensure_binary("cardano-address")

    print("Scavenger Wrangler")
    print(f"API URL       : {args.api_url}")
    print(f"Account       : {args.account} (ROLE=0 external)")
    print(f"Donors total  : {len(donors)}")
    print(f"Run directory : {run_dir}")
    print(f"Mode          : {'DRY-RUN' if args.dry_run else 'LIVE'}")
    if args.unassign:
        print("Operation     : UNASSIGN (self-assignment per donor)")
    else:
        print(f"Destination   : {dest_addr}")
    print()

    # Writers
    sig_f = signatures_csv_path.open("w", newline="", encoding="utf-8")
    sig_w = csv.writer(sig_f)
    sig_w.writerow(["index", "path", "address", "destination", "signature_hex"])

    results: List[DonationResult] = []

    api_session = requests.Session()
    api_session.headers.update({"User-Agent": args.user_agent})

    with log_path.open("a", encoding="utf-8") as log_f:
        for row in donors:
            dest_for_row = row.address if args.unassign else dest_addr  # type: ignore[arg-type]
            # Per-row validation in unassign mode (catches network mismatches from CSV)
            validate_destination_address(dest_for_row, args.network_tag)

            print("-" * 72)
            print(f"index={row.index} ROLE={row.role} path={row.path}")
            print(f"  donor: {row.address}")
            print(f"  dest : {dest_for_row}")

            signature_hex: Optional[str] = None
            donation_id: Optional[str] = None
            solutions_consolidated: Optional[int] = None
            http_code: int = 0
            body_text: str = ""
            status_class: str = "dry_run" if args.dry_run else "other"

            with tempfile.TemporaryDirectory(prefix="donate-to-") as tmpdir:
                tmp = Path(tmpdir)
                try:
                    skey_path = derive_skey(mnemonic, args.account, row.role, row.index, tmp)
                    signature_hex, _pubkey_hex = cip8_sign(skey_path, row.address, dest_for_row)
                except Exception as e:
                    print(f"  ERROR during derive/sign: {e}")
                    status_class = "sign_error"
                    result = DonationResult(
                        line_no=row.line_no,
                        index=row.index,
                        role=row.role,
                        path=row.path,
                        address=row.address,
                        destination=dest_for_row,
                        http_code=0,
                        status_class=status_class,
                        donation_id=None,
                        solutions_consolidated=None,
                        signature_hex=None,
                        response_raw=str(e),
                    )
                    log_f.write(json.dumps(asdict(result)) + "\n")
                    log_f.flush()
                    results.append(result)
                    continue

                # Log signature immediately
                sig_w.writerow([row.index, row.path, row.address, dest_for_row, signature_hex])
                sig_f.flush()

                if args.dry_run:
                    print("  dry-run: not calling API; signature logged.")
                    result = DonationResult(
                        line_no=row.line_no,
                        index=row.index,
                        role=row.role,
                        path=row.path,
                        address=row.address,
                        destination=dest_for_row,
                        http_code=0,
                        status_class="dry_run",
                        donation_id=None,
                        solutions_consolidated=None,
                        signature_hex=signature_hex,
                        response_raw="",
                    )
                    log_f.write(json.dumps(asdict(result)) + "\n")
                    log_f.flush()
                    results.append(result)
                    if args.per_request_delay > 0:
                        time.sleep(args.per_request_delay)
                    continue

                # Call /donate_to with 429 handling
                attempts_429 = 0
                is_network_error = False
                while True:
                    try:
                        resp = donate_to(args.api_url, dest_for_row, row.address, signature_hex, session=api_session)
                        http_code = resp.status_code
                        body_text = resp.text
                        is_network_error = False
                    except requests.RequestException as e:
                        http_code = 0
                        body_text = str(e)
                        is_network_error = True

                    if http_code == 429 and not is_network_error:
                        attempts_429 += 1
                        print(f"  HTTP 429 (Too Many Requests) attempt {attempts_429}/{args.max429}")
                        if attempts_429 >= max(args.max429, 1):
                            break
                        retry_after = 0.0
                        try:
                            retry_after = float(resp.headers.get("Retry-After", "0"))
                        except Exception:
                            retry_after = 0.0
                        delay = retry_after if retry_after > 0 else args.backoff_base * (2 ** (attempts_429 - 1))
                        print(f"  Sleeping {delay:.1f}s before retry...")
                        time.sleep(delay)
                        continue
                    else:
                        break

                # Parse JSON if available
                resp_json: Optional[dict] = None
                if body_text:
                    try:
                        resp_json = json.loads(body_text)
                    except Exception:
                        resp_json = None

                status_class = classify_status(http_code, is_network_error=is_network_error)
                if resp_json and isinstance(resp_json, dict):
                    donation_id = resp_json.get("donation_id") or resp_json.get("donationId")
                    val = resp_json.get("solutions_consolidated") or resp_json.get("Solutions_consolidated")
                    try:
                        solutions_consolidated = int(val) if val is not None else None
                    except Exception:
                        solutions_consolidated = None

                print(f"  HTTP status: {http_code} -> {status_class}")
                if donation_id:
                    print(f"  donation_id: {donation_id}")
                if solutions_consolidated is not None:
                    print(f"  solutions_consolidated: {solutions_consolidated}")
                if body_text:
                    print(f"  resp: {body_text[:400]}")

                result = DonationResult(
                    line_no=row.line_no,
                    index=row.index,
                    role=row.role,
                    path=row.path,
                    address=row.address,
                    destination=dest_for_row,
                    http_code=http_code,
                    status_class=status_class,
                    donation_id=donation_id,
                    solutions_consolidated=solutions_consolidated,
                    signature_hex=signature_hex,
                    response_raw=body_text,
                )
                log_f.write(json.dumps(asdict(result)) + "\n")
                log_f.flush()
                results.append(result)

                if http_code != 429 and args.per_request_delay > 0:
                    time.sleep(args.per_request_delay)

    sig_f.close()

    # Write summary.csv
    with summary_csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["index", "path", "address_from", "address_to", "http_code",
                    "status_class", "donation_id", "solutions_consolidated"])
        for r in results:
            solutions_val = r.solutions_consolidated if r.solutions_consolidated is not None else ""
            w.writerow([
                r.index,
                r.path,
                r.address,
                r.destination,
                r.http_code,
                r.status_class,
                r.donation_id or "",
                solutions_val,
            ])

    # Write human-readable job_summary.txt
    assigned = 0
    failed = 0
    unassigned = 0
    lines: List[str] = []
    lines.append("=== Scavenger Consolidation Job Summary ===")
    lines.append(f"run_folder     : {run_dir.name}")
    if args.unassign:
        lines.append("destination    : UNASSIGN (self-assignment per donor)")
    else:
        lines.append(f"destination    : {dest_addr}")
    lines.append(f"mode           : {'DRY-RUN' if args.dry_run else 'LIVE'}")
    lines.append(f"total_donors   : {len(results)}")
    lines.append("")
    lines.append("Results:")
    for r in results:
        bucket = human_bucket(r.status_class, args.dry_run, r.address, r.destination)
        if bucket == "assigned":
            assigned += 1
            lines.append(f"- {r.address}: assigned -> {r.destination}")
        elif bucket == "unassigned":
            unassigned += 1
            lines.append(f"- {r.address}: unassigned -> {r.address}")
        else:
            failed += 1
            note = ""
            if r.status_class == "not_registered":
                note = " (not registered)"
            elif r.status_class == "already_assigned":
                note = " (already assigned)"
            elif r.status_class == "sign_error":
                note = " (signing error)"
            elif r.status_class == "client_error":
                note = " (client error)"
            elif r.status_class == "server_error":
                note = " (server error)"
            elif r.status_class == "rate_limited":
                note = " (rate limited)"
            elif r.status_class == "network_error":
                note = " (network error)"
            lines.append(f"- {r.address}: failed{note}")
    lines.append("")
    lines.append(f"assigned   : {assigned}")
    lines.append(f"unassigned : {unassigned}")
    lines.append(f"failed     : {failed}")
    lines.append("")
    lines.append("Artifacts:")
    lines.append(f"- log.jsonl        : {log_path}")
    lines.append(f"- summary.csv      : {summary_csv_path}")
    lines.append(f"- signatures.csv   : {signatures_csv_path}")

    with job_summary_path.open("w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print("\nWrote:")
    print(f"  {log_path}")
    print(f"  {summary_csv_path}")
    print(f"  {signatures_csv_path}")
    print(f"  {job_summary_path}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user.", file=sys.stderr)
        sys.exit(130)
