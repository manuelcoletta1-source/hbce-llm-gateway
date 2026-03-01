#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

def die(msg: str, code: int = 2):
    raise SystemExit(msg)

def read_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def write_json(path: str, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")

def sha256_hex_utf8_canon(s: str) -> str:
    # Canonicalize CRLF -> LF to match the verifier and mk_event tool
    b = str(s).replace("\r\n", "\n").encode("utf-8")
    return hashlib.sha256(b).hexdigest()

def openssl_sign_ed25519(privkey_path: str, message_ascii: str) -> str:
    if not os.path.isfile(privkey_path):
        die(f"DENY: missing private key: {privkey_path}")

    payload_path = os.path.join(REPO_ROOT, ".tmp_payload_sigpatch.txt")
    sig_bin_path = os.path.join(REPO_ROOT, ".tmp_sig_sigpatch.bin")

    with open(payload_path, "wb") as f:
        f.write(message_ascii.encode("ascii"))

    cmd = [
        "openssl", "pkeyutl",
        "-sign",
        "-inkey", privkey_path,
        "-rawin",
        "-in", payload_path,
        "-out", sig_bin_path
    ]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        die("DENY: OpenSSL sign failed:\n" + (r.stderr or r.stdout or ""))

    with open(sig_bin_path, "rb") as f:
        sig_b64 = base64.b64encode(f.read()).decode("ascii")

    # cleanup best-effort
    try:
        os.remove(payload_path)
        os.remove(sig_bin_path)
    except Exception:
        pass

    return sig_b64

def main():
    ap = argparse.ArgumentParser(description="HBCE LLM Gateway — patch signature for an existing event (fail-closed).")
    ap.add_argument("--event-id", type=int, required=True)
    ap.add_argument("--privkey", default="/home/manuelcoletta1/joker-c2.key")
    ap.add_argument("--policy", default="policy/UE-ΦΩ-001.json")
    args = ap.parse_args()

    event_path = os.path.join(REPO_ROOT, "events", f"{args.event_id:06d}.json")
    if not os.path.isfile(event_path):
        die(f"DENY: event not found: {event_path}")

    policy_path = os.path.join(REPO_ROOT, args.policy)
    pol = read_json(policy_path)

    ev = read_json(event_path)

    # Policy: signature required?
    enf = (pol.get("enforcement") or {})
    sig_required = bool(enf.get("signature_required"))
    min_id = int(enf.get("signature_required_from_event_id") or 0)
    if sig_required and args.event_id >= min_id:
        # ok, must be signed
        pass
    else:
        die("DENY: policy says signature is not required for this event_id (refuse to patch).")

    # Recompute canonical hashes
    input_canon = (ev.get("input") or {}).get("canonical")
    output_canon = (ev.get("output") or {}).get("canonical")
    if input_canon is None or output_canon is None:
        die("DENY: missing input/output canonical text")

    input_sha = sha256_hex_utf8_canon(input_canon)
    output_sha = sha256_hex_utf8_canon(output_canon)

    # Check stored hashes
    if (ev.get("input") or {}).get("sha256") != input_sha:
        die("FAIL: input.sha256 mismatch (event content not canonical)")
    if (ev.get("output") or {}).get("sha256") != output_sha:
        die("FAIL: output.sha256 mismatch (event content not canonical)")

    prev = (ev.get("chain") or {}).get("prev")
    entry_stored = (ev.get("chain") or {}).get("entry")
    policy_pack_id = (ev.get("policy") or {}).get("policy_pack_id")
    ts = ev.get("ts")
    ipr_ai = ev.get("ipr_ai")
    ipr_operator = ev.get("ipr_operator")

    for k, v in [
        ("chain.prev", prev),
        ("chain.entry", entry_stored),
        ("policy.policy_pack_id", policy_pack_id),
        ("ts", ts),
        ("ipr_ai", ipr_ai),
        ("ipr_operator", ipr_operator),
    ]:
        if v is None or v == "":
            die(f"DENY: missing {k}")

    base = "|".join([prev, input_sha, output_sha, policy_pack_id, ts, ipr_ai, ipr_operator])
    entry = hashlib.sha256(base.encode("utf-8")).hexdigest()

    if entry != entry_stored:
        die("FAIL: chain.entry mismatch (event chain is inconsistent)")

    # Sign ascii(entry)
    sig_b64 = openssl_sign_ed25519(args.privkey, entry)

    # Patch
    if "sign" not in ev or not isinstance(ev["sign"], dict):
        ev["sign"] = {}
    ev["sign"]["alg"] = "ED25519"
    ev["sign"]["sig"] = sig_b64

    write_json(event_path, ev)

    print(json.dumps({
        "ok": True,
        "event_id": args.event_id,
        "entry_sha256": entry,
        "sig_b64_head": sig_b64[:16],
        "sig_b64_tail": sig_b64[-16:],
        "patched_file": f"events/{args.event_id:06d}.json"
    }, indent=2))

if __name__ == "__main__":
    main()
