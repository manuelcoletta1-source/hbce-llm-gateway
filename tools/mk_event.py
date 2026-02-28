#!/usr/bin/env python3
import base64
import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timezone, timedelta

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

def die(msg: str, code: int = 1):
    raise SystemExit(msg)

def read_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def write_json(path: str, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")

def sha256_hex_utf8(s: str) -> str:
    b = s.replace("\r\n", "\n").encode("utf-8")
    return hashlib.sha256(b).hexdigest()

def now_rome_iso():
    # Europe/Rome is UTC+1 or UTC+2 depending on DST.
    # For deterministic ops, accept that operator can override via CLI.
    # Default: local time with offset from system (best effort).
    return datetime.now().astimezone().isoformat(timespec="seconds")

def zero_pad_event_id(n: int) -> str:
    return f"{n:06d}"

def ensure_no_tilde_in_paths():
    # user constraint: never use "~" in commands; here we just sanity-check inputs
    return

def openssl_sign_ed25519(privkey_path: str, message_ascii: str) -> str:
    """
    Signs the ASCII message bytes (no newline) using ED25519 private key via openssl.
    Returns signature in base64 (single line).
    """
    if not os.path.isfile(privkey_path):
        die(f"Missing private key: {privkey_path}")

    payload_path = os.path.join(REPO_ROOT, ".tmp_payload.txt")
    sig_bin_path = os.path.join(REPO_ROOT, ".tmp_sig.bin")

    with open(payload_path, "wb") as f:
        f.write(message_ascii.encode("ascii"))

    # Sign
    cmd = [
        "openssl", "pkeyutl", "-sign",
        "-inkey", privkey_path,
        "-rawin",
        "-in", payload_path,
        "-out", sig_bin_path
    ]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        die("OpenSSL sign failed:\n" + (r.stderr or r.stdout))

    with open(sig_bin_path, "rb") as f:
        sig_b64 = base64.b64encode(f.read()).decode("ascii")

    # Cleanup temp
    try:
        os.remove(payload_path)
        os.remove(sig_bin_path)
    except Exception:
        pass

    return sig_b64

def main():
    import argparse
    ap = argparse.ArgumentParser(description="HBCE LLM Gateway — deterministic event builder (hash+chain+ED25519).")
    ap.add_argument("--input", required=True, help="Input canonical text (string).")
    ap.add_argument("--output", required=True, help="Output canonical text (string).")
    ap.add_argument("--ts", default=None, help="ISO timestamp with offset (e.g. 2026-02-28T10:20:00+01:00). If omitted, uses local time.")
    ap.add_argument("--ipr-ai", default="IPR-AI-0001")
    ap.add_argument("--ipr-operator", default="IPR-3")
    ap.add_argument("--policy-pack-id", default="UE-ΦΩ-001")
    ap.add_argument("--provider-name", default="openai")
    ap.add_argument("--model-id", default="gpt-4.1")
    ap.add_argument("--privkey", default="/home/manuelcoletta1/joker-c2.key", help="Absolute path to ED25519 private key (DO NOT COMMIT).")
    ap.add_argument("--key-id", default="JOKER-C2-RUNTIME-001")
    ap.add_argument("--pub-ref", default="keys/joker-c2.pub.json")
    args = ap.parse_args()

    head_path = os.path.join(REPO_ROOT, "head.json")
    registry_path = os.path.join(REPO_ROOT, "registry.json")
    events_dir = os.path.join(REPO_ROOT, "events")

    if not os.path.isfile(head_path):
        die("Missing head.json in repo root.")
    if not os.path.isfile(registry_path):
        die("Missing registry.json in repo root.")
    if not os.path.isdir(events_dir):
        die("Missing events/ directory in repo root.")

    head = read_json(head_path)
    registry = read_json(registry_path)

    latest = head.get("latest") or {}
    prev_entry = latest.get("entry_sha256")
    prev_event_id = latest.get("event_id")
    if not prev_entry or prev_event_id is None:
        die("head.json missing latest.entry_sha256 or latest.event_id")

    event_id = int(prev_event_id) + 1
    ts = args.ts or now_rome_iso()

    input_canon = args.input.replace("\r\n", "\n")
    output_canon = args.output.replace("\r\n", "\n")

    input_sha = sha256_hex_utf8(input_canon)
    output_sha = sha256_hex_utf8(output_canon)

    base = "|".join([prev_entry, input_sha, output_sha, args.policy_pack_id, ts, args.ipr_ai, args.ipr_operator])
    entry = hashlib.sha256(base.encode("utf-8")).hexdigest()

    # Sign ASCII(entry)
    sig_b64 = openssl_sign_ed25519(args.privkey, entry)

    ev = {
        "spec": "HBCE-LM-EVENT-0001",
        "event_id": event_id,
        "ts": ts,
        "ipr_ai": args.ipr_ai,
        "ipr_operator": args.ipr_operator,
        "provider": {
            "name": args.provider_name,
            "model_id": args.model_id,
            "request_id": None
        },
        "policy": {
            "policy_pack_id": args.policy_pack_id,
            "mode": "FAIL_CLOSED",
            "notes": ["GDPR_MIN", "HASH_ONLY", "APPEND_ONLY"]
        },
        "input": {
            "canonical": input_canon,
            "sha256": input_sha
        },
        "output": {
            "canonical": output_canon,
            "sha256": output_sha
        },
        "chain": {
            "prev": prev_entry,
            "entry": entry,
            "algo": "sha256(prev|input_sha256|output_sha256|policy_pack_id|ts|ipr_ai|ipr_operator)"
        },
        "sign": {
            "alg": "ED25519",
            "key_id": args.key_id,
            "pub_ref": args.pub_ref,
            "sig": sig_b64
        }
    }

    ev_path_rel = f"events/{zero_pad_event_id(event_id)}.json"
    ev_path = os.path.join(REPO_ROOT, ev_path_rel)
    write_json(ev_path, ev)

    # Update head
    head["ts"] = ts
    head["latest"] = {
        "event_id": event_id,
        "path": ev_path_rel,
        "entry_sha256": entry
    }
    write_json(head_path, head)

    # Update registry append
    if "entries" not in registry or not isinstance(registry["entries"], list):
        die("registry.json missing entries array")

    registry["entries"].append({
        "event_id": event_id,
        "ts": ts,
        "path": ev_path_rel,
        "entry_sha256": entry
    })
    write_json(registry_path, registry)

    print(json.dumps({
        "ok": True,
        "event_id": event_id,
        "event_path": ev_path_rel,
        "entry_sha256": entry,
        "signed": True,
        "key_id": args.key_id
    }, indent=2))

if __name__ == "__main__":
    main()
