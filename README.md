# Scavenger Wrangler — Midnight Scavenger Consolidation

## Goal

Consolidate **Midnight Scavenger Mine allocations** from many mining wallets into a **single Cardano address**, or **undo** a consolidation by assigning each donor back to itself, using the official `donate_to` API endpoint.

This tool:

- Derives keys from a 15/24-word mnemonic (CIP-1852)
- Signs the exact CIP-8 message required by the Scavenger API
- Calls `POST /donate_to/<dest>/<original>/<signature>` per donor

It is a **slim, scriptable utility** intended for advanced users who understand the risks of working directly with mnemonics and signing keys.

## Why? 

Most of the tools I found depended on a wallet connection or other silliness. Since the mnemonics used for the scavenger hunt in most cases
are considered throwaway accounts, we can use it to derive the addresses and perform the entire operation in one fell swoop.

---

## Requirements

- **Python** 3.8+
- `pip install requests`
- **cardano-signer** in PATH (key derivation & CIP-8 signing)  
  Repo: <https://github.com/gitmachtl/cardano-signer>
- **cardano-address** in PATH (if you want the tool to **derive** base addr1… from your mnemonic)  
  Repo: <https://github.com/IntersectMBO/cardano-addresses>

Check your PATH:

```bash
which cardano-signer
which cardano-address
```

> **Security note:** Passing mnemonics on the CLI means they may appear in shell history and process lists. Use with care.

---

## Derivation model (CIP-1852)

We derive **base (delegated) addresses** on the **external chain** only:

```text
m / 1852' / 1815' / ACCOUNT' / 0 / INDEX
```

Internally:

1. A payment xpub is derived at role/index: `0 / INDEX`
2. An enterprise payment address is built from the payment xpub
3. Delegation is added via the stake xpub (`2/0`) to produce a **base addr1…**

All donors are treated as **ROLE = 0 (external)**.

---

## CIP-8 message & API call

For each donor address:

1. Derive the signing key from your mnemonic (CIP-1852 path)

2. Sign the message:

   ```text
   Assign accumulated Scavenger rights to: <DESTINATION_ADDRESS>
   ```

3. Call:

   ```text
   POST /donate_to/<dest>/<original>/<signature>
   ```

---

## Modes of operation

Scavenger Wrangler supports three main modes:

1. **Derive-only** (no signing, no API calls)
2. **Consolidate** (many → one destination)
3. **Unassign** (donor → donor; per-address self-assignment)

You can supply donors from:

- A **CSV file**
- **Derived addresses** from a mnemonic
- Or **both** (processed in order: CSV first, then derived)

---

## 1) Derive addresses only (no signing, no API calls)

Use this to verify that the derived addresses match your scavenger challenges (or just to inspect the derivation).

```bash
python3 scavenger-wrangler.py \
  --mnemonic "your 24 or 15 words ..." \
  --numaddresses 25 \
  --derive-address-only
```

### What it does

- Derives the first N external base addresses at: `m / 1852' / 1815' / ACCOUNT' / 0 / INDEX`
- **Does not** sign anything or call any API

### Output

- Prints 25 addresses to **stdout**
- Creates a run folder:

  ```text
  consolidate-logs/run-YYYYMMDDTHHMMSSZ/
      derived_addresses.txt   # one addr per line
      derived_addresses.csv   # index, path, address
      job_summary.txt         # derive-only job summary
  ```

---

## 2) Dry-run a consolidation (signatures only, no API)

Use this to verify derivation paths and signatures without touching the Scavenger API.

```bash
python3 scavenger-wrangler.py \
  --mnemonic "your 24 or 15 words ..." \
  --destination-addr "addr1qDESTINATION..." \
  --numaddresses 25 \
  --dry-run
```

### CSV donors (optional)

You can also supply donors via CSV:

```bash
python3 scavenger-wrangler.py \
  --mnemonic "your 24 or 15 words ..." \
  --destination-addr "addr1qDESTINATION..." \
  --csv donors.csv \
  --dry-run
```

**CSV format (header required):**

```csv
index,external,address
0,1,addr1q...
1,1,addr1q...
```

- `external` is **ignored** in this tool (we always treat donors as external chain)
- The `index` is used to derive the CIP-1852 path

### What happens in dry-run

- For each donor:
  - Derives the signing key from your mnemonic
  - Signs the CIP-8 message
  - **Does not call the API**
- Signatures are logged to `signatures.csv` and `log.jsonl`

---

## 3) Live consolidation (many → one destination)

This is the normal consolidation flow: assign **many donors** to a **single destination address**.

```bash
python3 scavenger-wrangler.py \
  --mnemonic "your 24 or 15 words ..." \
  --destination-addr "addr1qDESTINATION..." \
  --numaddresses 25 \
  --per-request-delay 1.0 \
  --max429 6 \
  --backoff-base 5.0
```

You can also combine CSV and derivation:

```bash
python3 scavenger-wrangler.py \
  --mnemonic "your 24 or 15 words ..." \
  --destination-addr "addr1qDESTINATION..." \
  --csv donors.csv \
  --numaddresses 25
```

Donors are processed in this order:

1. All rows from `--csv`
2. Derived addresses from `--numaddresses`

> Note: There is **no deduplication**; if the same address appears twice, it will be processed twice.

### Rate limiting

- HTTP `429` responses trigger exponential backoff:
  - base delay = `--backoff-base` seconds
  - up to `--max429` retries per address
- A minimum `--per-request-delay` is applied after each **non-429** response

---

## 4) Unassign / donate back to self (`--unassign`)

To **undo** consolidation, you should reassign each donor address to **itself**. Scavenger Wrangler does this via `--unassign`:

```bash
python3 scavenger-wrangler.py \
  --mnemonic "your 24 or 15 words ..." \
  --csv donors.csv \
  --unassign
```

Or using derived addresses:

```bash
python3 scavenger-wrangler.py \
  --mnemonic "your 24 or 15 words ..." \
  --numaddresses 25 \
  --unassign
```

### Behavior

- For each donor address:
  - Destination is set to the **same** address: `destination = donor`
  - Signs:
    ```text
    Assign accumulated Scavenger rights to: <DONOR_ADDRESS>
    ```
  - Calls:
    ```text
    POST /donate_to/<donor>/<donor>/<signature>
    ```
- `--destination-addr` is **ignored** when `--unassign` is set

In the job summary, successful self-assignments are counted in the **unassigned** bucket (see below).

---

## Outputs (per job / run folder)

All runs (except derive-only) write to:

```text
consolidate-logs/
  run-YYYYMMDDTHHMMSSZ/
    log.jsonl          # detailed JSON per donor (status code, donation_id, signature, response text)
    summary.csv        # index, path, address_from, address_to, http_code, status_class, donation_id, solutions_consolidated
    signatures.csv     # index, path, address, destination, signature_hex
    job_summary.txt    # human-readable summary
```

Derive-only runs write:

```text
consolidate-logs/
  run-YYYYMMDDTHHMMSSZ/
    derived_addresses.txt    # one addr per line
    derived_addresses.csv    # index, path, address
    job_summary.txt          # derive-only summary
```

### `job_summary.txt`

Human-first summary with three buckets:

- **assigned**
  - API returned `success` or `already_assigned`
  - And the destination is **different** from the donor

- **unassigned**
  - Dry-run entries, or
  - Successful **self-assignments** (destination == donor; e.g. `--unassign`)

- **failed**
  - `not_registered`, `client_error`, `server_error`, `rate_limited`, `sign_error`, `network_error`, `other`

Example:

```text
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
- log.jsonl        : /path/to/log.jsonl
- summary.csv      : /path/to/summary.csv
- signatures.csv   : /path/to/signatures.csv
```

In **unassign** mode, you'll see lines like:

```text
- addr1qXYZ...: unassigned -> addr1qXYZ...
```

---

## Common errors & tips

- **404 Not Registered**  
  The donor address was never registered with the mining process. You can ignore these or handle them separately.

- **409 Already Assigned**  
  The donor already points to a destination. Treated as **assigned** (idempotent).

- **400 Invalid Signature**  
  Ensure:
  - The message is exactly:
    ```text
    Assign accumulated Scavenger rights to: <DESTINATION_ADDRESS>
    ```
  - You signed with the **donor's** key at the correct derivation path: `m / 1852' / 1815' / ACCOUNT' / 0 / INDEX`

- **429 Too Many Requests**  
  Increase `--per-request-delay` or rerun later. The tool already backs off exponentially up to `--max429` times.

- **Addresses don't start with `addr1` / `addr_test1`**  
  You must use **base addresses** (payment + delegation). This tool uses `cardano-address` to build base addresses from payment + stake xpubs.

- **Mnemonic word count warning**  
  The script warns if the mnemonic is not 12/15/18/21/24 words. That's a sanity check only; it doesn't block execution.

---

## Security

- Your mnemonic never leaves your machine
- Keys are generated in a **temporary directory** per donor and removed when the process exits
- Logs contain signatures and raw API responses; treat them as sensitive
- Use a dedicated machine or account where possible
- Always test on a **small batch** first using:
  - `--derive-address-only` to confirm addresses
  - `--dry-run` to confirm signatures and paths

---

## CLI reference

```text
usage: scavenger-wrangler.py
  --mnemonic "…"
  [--derive-address-only --numaddresses N]
  [--unassign]
  [--destination-addr addr1…]
  [--csv donors.csv]
  [--numaddresses N]
  [--account 0]
  [--network-tag mainnet|testnet]
  [--api-url URL]
  [--user-agent UA]
  [--per-request-delay 1.0]
  [--max429 6]
  [--backoff-base 5.0]
  [--out-dir DIR]
  [--log-file PATH]
  [--dry-run]
```

### Key flags

- `--mnemonic`  
  BIP-style mnemonic (15 or 24 words typical for Shelley/Yoroi; 12/18/21 also allowed, with a warning if non-standard).

- `--derive-address-only`  
  Derive addresses and write artifacts; **no signing**, **no API calls**. Requires `--numaddresses`.

- `--destination-addr addr1…`  
  Consolidation destination address (required **unless** `--unassign` or `--derive-address-only`).

- `--unassign`  
  Assign each donor address **to itself** (self-assignment). Ignores `--destination-addr`.

- `--csv donors.csv`  
  Donor CSV with columns: `index,external,address`  
  (`external` is ignored; donors are treated as external chain).

- `--numaddresses N`  
  Derive the first N external addresses from the mnemonic.

- `--account N`  
  HD account index (default `0`).

- `--network-tag mainnet|testnet`  
  Network tag for derivation (default `mainnet`). The tool does basic consistency checks between the tag and the address prefix (`addr1` vs `addr_test1`).

- `--dry-run`  
  Sign and log signatures but **do not call** the Scavenger API.

- `--out-dir DIR`  
  Base output folder for run subfolders (default `consolidate-logs`).

- `--log-file PATH`  
  Custom JSONL log path. If provided, the log file may live **outside** the run folder.

---

## Disclaimer

This tool is provided **as-is**, without any warranty of correctness, security, or fitness for any particular purpose.

- It may contain bugs or incorrect behavior
- You are responsible for verifying all actions it takes with small test runs first
- Always keep secure backups of your mnemonics and logs
- This toolkit is community-authored and not affiliated with Midnight or any other entity

Use at your own risk. Test with a few addresses before processing large batches.
This is licensed with the MIT license, so feel free to do with it as you please. 
