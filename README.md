# Midnight Scavenger Consolidation — v0.1

**Goal:** consolidate Scavenger Mine allocations from many mining wallets into a **single Cardano address** using the official `donate_to` API endpoint.  

**Why?** Most solutions depend on wallet integration or otherwise. This only requires your 15 or 24 word mnemonic. 

Since the mnemonics used in the scavenger hunt are throwaway, why not use that to derive the entire chain?

Well, there are a few dependencies, the most important being:
- Python 3.10 or something newer, maybe?
- Cardano-addresses: https://github.com/IntersectMBO/cardano-addresses
- Cardano-signer: https://github.com/gitmachtl/cardano-signer

## Requirements

- **Python** 3.8+
- `pip install requests`
- **cardano‑signer** in `PATH` (for key derivation & CIP‑8 signing)
- **cardano‑address** in `PATH` (if you want the tool to **derive** `addr1…` from your mnemonic)

> **Check your path**
> ```bash
> which cardano-signer
> which cardano-address
> ```

---

## Derivation model (CIP‑1852)

We derive **base addresses** (delegated) on the external chain only:
```
m / 1852' / 1815' / ACCOUNT' / 0 / INDEX
```
Internally, we construct an enterprise address from the **payment xpub** and then **delegate** with the **stake xpub** to yield an `addr1…` base address.

---

## Quick Start (slim tool)

### 1) Derive addresses only (no signing, no API calls)

```bash
python3 consolidate_scavenger.py \
  --mnemonic "your 24 or 15 words ..." \
  --numaddresses 25 \
  --account 0 \
  --network-tag mainnet \
  --derive-address-only \
  --out-dir consolidate-logs
```

**Output**
- prints 25 addresses to **stdout**
- creates a run folder:
  ```
  consolidate-logs/run-YYYYMMDDTHHMMSSZ/
    derived_addresses.txt   # one addr per line
    derived_addresses.csv   # index, path, address
    job_summary.txt         # describe the derive-only job
  ```

### 2) Dry‑run a consolidation (signatures only)

```bash
python3 consolidate_scavenger.py \
  --mnemonic "your 24 or 15 words ..." \
  --destination-addr "addr1qDESTINATION..." \
  --csv donors.csv \
  --dry-run \
  --out-dir consolidate-logs
```

**CSV format (header required):**
```csv
index,external,address
0,1,addr1q...
1,1,addr1q...
```
> The `external` column is **ignored** in this simplified tool (we always treat donors as external chain).

### 3) Live consolidation

```bash
python3 consolidate_scavenger.py \
  --mnemonic "your 24 or 15 words ..." \
  --destination-addr "addr1qDESTINATION..." \
  --csv donors.csv \
  --per-request-delay 1.0 \
  --max429 6 \
  --backoff-base 5.0 \
  --out-dir consolidate-logs
```

**What happens**
1. For each donor address, the tool **derives** the signing key from your mnemonic (CIP‑1852).
2. Signs the exact message:
   ```
   Assign accumulated Scavenger rights to: <DESTINATION_ADDRESS>
   ```
3. Calls:
   ```
   POST /donate_to/<dest>/<original>/<signature>
   ```
4. Handles common outcomes:
   - `200` → **success** (assigned)
   - `409` → **already assigned** (treated as assigned)
   - `404` → **not registered** (failed)
   - `429` → backoff with exponential delay (up to `--max429`)

---

## Outputs (per job / run folder)

```
consolidate-logs/
  run-YYYYMMDDTHHMMSSZ/
    log.jsonl          # detailed row per donor (status code, donation_id, signature, response text)
    summary.csv        # index, path, address_from, address_to, code, status_class, donation_id, solutions_consolidated
    signatures.csv     # index, path, address, destination, signature_hex
    job_summary.txt    # human-readable checklist

For derived address run:

consolidate-logs/
  run-YYYYMMDDTHHMMSSZ/
    derived_addresses.txt    # one addr per line
    derived_addresses.csv    # index, path, address
    job_summary.txt          # derive-only summary
```

### `job_summary.txt`

Human-first summary with three buckets:

- **assigned**: API returned `success` or `already_assigned`
- **unassigned**: dry‑run; or `success` to **self** (donate‑back undo)
- **failed**: everything else (`not_registered`, `client_error`, `server_error`, `rate_limited`, `sign_error`, `other`)

Example:
```
=== Scavenger Consolidation Job Summary ===
run_folder     : run-20251116T104512Z
destination    : addr1qDEST...
mode           : LIVE
total_donors   : 123

Results:
- addr1qABC...: assigned -> addr1qDEST...
- addr1qDEF...: failed (not registered)
- addr1qGHI...: assigned -> addr1qDEST...
...

assigned   : 97
unassigned : 0
failed     : 26

Artifacts:
- log.jsonl
- summary.csv
- signatures.csv
```

---

## Undo / donate back to self

To **undo** an existing assignment for a donor, donate back to the **same** address:
```
destination = original
```
The tool classifies such a `success` as **unassigned** in the job summary.

---

## Advanced (optional)

### Full consolidator

`consolidate_scavenger_maxi.py` has a few extra knobs that you won't get here:
- separate **User‑Agent** and **jittered pacing** for stats calls
- ability to **verify recipient** or **filter donors that mined** (not needed for normal runs)
- keep or disable with flags; defaults are polite and resume‑safe

(*This simplified tool doesn’t call stats at all.*)

---

## Common errors & tips

- **404 Not Registered**  
  The donor address was never registered with the mining process. You can ignore or handle separately.
- **409 Already Assigned**  
  The donor already points to a destination. Treated as **assigned** for idempotent runs.
- **400 Invalid Signature**  
  Ensure the message is **exactly**:
  `Assign accumulated Scavenger rights to: <DESTINATION_ADDRESS>`
  and that you signed with the **donor’s** key at the correct derivation path.
- **429 Too Many Requests**  
  Increase `--per-request-delay` or rerun later. The tool already does exponential backoff.
- **Addresses don’t start with `addr1`**  
  You need **base** addresses (payment + delegation). This toolkit builds base addresses via `cardano-address`.
- **15 vs 24 words**  
  Both are supported (Shelley/Yoroi mnemonics). 12‑word (Exodus‑style) is **not** in scope for this tool.

---

## Security

- Your mnemonic never leaves your machine.
- Keys are generated in a **temporary directory** per donor and discarded after signing.
- Treat logs and signatures as sensitive artifacts; store accordingly.
- Use a dedicated machine/account if possible.

---

## CLI reference

```
usage: consolidate_scavenger.py
  --mnemonic "…"
  [--derive-address-only --numaddresses N]
  [--destination-addr addr1…]
  [--csv donors.csv]
  [--numaddresses N] [--account 0] [--network-tag mainnet|testnet]
  [--api-url URL] [--user-agent UA]
  [--per-request-delay 1.0] [--max429 6] [--backoff-base 5.0]
  [--out-dir DIR] [--log-file PATH] [--dry-run]
```

- `--derive-address-only` — **print addresses and exit** (no signing, no API). Requires `--numaddresses`.
- `--csv` — donor CSV (`index,external,address`). `external` is ignored; donors are treated as external chain.
- `--numaddresses` — derive the first N external addresses from the mnemonic.
- `--account` — HD account (default `0`).
- `--network-tag` — `mainnet` (default) or `testnet`.
- `--dry-run` — sign and log, **no API calls**.
- `--out-dir` — base output folder for run subfolders (default `consolidate-logs`).

---

## Disclaimer

This project is currently a work in progress. It is provided as-is, without any warranty of correctness, functionality, or fitness for any particular purpose. There is no guarantee that it works as intended, and it may contain bugs, incomplete features, or incorrect cryptographic behavior.

Do not use this software for security-critical or production purposes. Use at your own risk. Use at your own risk. Verify small batches first (e.g., `--dry-run` and a few addresses) before processing hundreds. Always keep secure backups of your mnemonic and logs. This toolkit is community‑authored and not affiliated with Midnight, or anyone else. This software is licensed under the MIT license. Have at it.
