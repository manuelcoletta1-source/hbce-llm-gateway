#!/usr/bin/env python3
import base64
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Ensure repo root is importable (so tools/ can import joker_c2_governor.py)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

try:
    from joker_c2_governor import joker_c2_gate, FailClosed
except Exception as e:
    joker_c2_gate = None
    FailClosed = Exception
    _IMPORT_ERR = e


def die(msg: str):
    raise SystemExit(str(msg))


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


def now_iso_local():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def zero_pad_event_id(n: int) -> str:
    return f"{n:06d}"


def openssl_sign_ed25519(privkey_path: str, message_ascii: str) -> str:
    if not os.path.isfile(privkey_path):
        die(f"Missing private key: {privkey_path}")

    payload_path = os.path.join(REPO_ROOT, ".tmp_payload.txt")
    sig_bin_path = os.path.join(REPO_ROOT, ".tmp_sig.bin")

    with open(payload_path, "wb") as f:
        f.write(message_ascii.encode("ascii"))

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

    try:
        os.remove(payload_path)
        os.remove(sig_bin_path)
    except Exception:
        pass

    return sig_b64


def _joker_required():
    if joker_c2_gate is None:
        die(f"FAIL_CLOSED: JOKER_C2_IMPORT_ERROR: {_IMPORT_ERR}")


def _load_request_from_path(p: str):
    if not p:
        return None
    if not os.path.isfile(p):
        die(f"FAIL_CLOSED: JOKER_REQUEST_NOT_FOUND: {p}")
    return read_json(p)


def main():
    import argparse
    ap = argparse.ArgumentParser(
        description="HBCE LLM Gateway — deterministic event builder (hash+chain+ED25519) with Joker-C2 pre-gate."
    )

    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--ts", default=None)

    ap.add_argument("--ipr-ai", default="IPR-AI-0001")
    ap.add_argument("--ipr-operator", default="IPR-3")
    ap.add_argument("--policy-pack-id", default="UE-ΦΩ-001")
    ap.add_argument("--provider-name", default="openai")
    ap.add_argument("--model-id", default="gpt-4.1")

    ap.add_argument("--privkey", default="/home/manuelcoletta1/joker-c2.key")
    ap.add_argument("--key-id", default="JOKER-C2-RUNTIME-001")
    ap.add_argument("--pub-ref", default="keys/joker-c2.pub.json")

    # Joker-C2 gating (fail-closed by default)
    ap.add_argument("--joker-core-dir", default=os.environ.get("JOKER_C2_CORE_DIR", "/home/manuelcoletta1/hbce-joker-c2-core"))
    ap.add_argument("--joker-out-dir", default=os.environ.get("JOKER_C2_OUT_DIR", "/home/manuelcoletta1/hbce-joker-c2-core/out"))
    ap.add_argument("--joker-request", default=os.environ.get("JOKER_C2_REQUEST_JSON", None),
                    help="Path to Joker-C2 request JSON. If omitted, tool fails closed unless --joker-mode OFF.")
    ap.add_argument("--joker-mode", default="REQUIRED", choices=["REQUIRED", "OFF"],
                    help="REQUIRED: must pass through Joker-C2 gate. OFF: bypass (NOT RECOMMENDED).")

    args = ap.parse_args()

    head_path = os.path.join(REPO_ROOT, "head.json")
    registry_path = os.path.join(REPO_ROOT, "registry.json")

    head = read_json(head_path)
    registry = read_json(registry_path)

    prev_entry = head["latest"]["entry_sha256"]
    prev_event_id = head["latest"]["event_id"]

    event_id = int(prev_event_id) + 1
    ts = args.ts or now_iso_local()

    input_canon = args.input.replace("\r\n", "\n")
    output_canon = args.output.replace("\r\n", "\n")

    input_sha = sha256_hex_utf8(input_canon)
    output_sha = sha256_hex_utf8(output_canon)

    # ----------------------------
    # JOKER-C2 PRE-GATE (FAIL-CLOSED)
    # ----------------------------
    joker = None
    joker_req_sha256 = None

    if args.joker_mode != "OFF":
        _joker_required()

        req = _load_request_from_path(args.joker_request)
        if req is None:
            die("FAIL_CLOSED: JOKER_REQUEST_MISSING (set --joker-request or JOKER_C2_REQUEST_JSON)")

        # deterministically bind request_id to event intent (no secrets)
        # keep any existing schema, just overwrite request_id when present.
        try:
            req["request_id"] = f"HBCE-LM-{zero_pad_event_id(event_id)}-{input_sha[:12]}-{output_sha[:12]}"
        except Exception:
            pass

        # hash canonical request (stable ordering)
        joker_req_sha256 = sha256_hex_utf8(json.dumps(req, indent=2, sort_keys=True, ensure_ascii=False) + "\n")

        try:
            res = joker_c2_gate(
                req,
                joker_c2_core_dir=args.joker_core_dir,
                out_dir=args.joker_out_dir,
            )
        except FailClosed as e:
            die("FAIL_CLOSED: " + str(e))
        except Exception as e:
            die("FAIL_CLOSED: JOKER_C2_GATE_ERROR: " + str(e))

        joker = {
            "status": res.status,          # PASS | DENY
            "entry_hash": res.entry_hash,  # opposable hash
            "request_sha256": joker_req_sha256,
            "core_dir": args.joker_core_dir,
            "out_dir": args.joker_out_dir,
        }
    else:
        joker = {
            "status": "BYPASS",
            "entry_hash": None,
            "request_sha256": None,
            "core_dir": None,
            "out_dir": None,
        }

    # ----------------------------
    # EVENT ENTRY HASH (CHAINED + GOVERNED)
    # Bind chain entry to Joker-C2 decision to make governance opposable.
    # ----------------------------
    joker_status = joker.get("status") if joker else "UNKNOWN"
    joker_entry = joker.get("entry_hash") if joker else None
    joker_bind = joker_entry if joker_entry else "NO_JOKER_ENTRY_HASH"

    base = "|".join([
        prev_entry,
        input_sha,
        output_sha,
        args.policy_pack_id,
        ts,
        args.ipr_ai,
        args.ipr_operator,
        joker_status,
        joker_bind
    ])
    entry = hashlib.sha256(base.encode("utf-8")).hexdigest()

    sig_b64 = openssl_sign_ed25519(args.privkey, entry)

    ev_path_rel = f"events/{zero_pad_event_id(event_id)}.json"

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

        # Joker-C2 governance decision (opposable)
        "joker_c2": joker,

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
            "algo": "sha256(prev|input_sha256|output_sha256|policy_pack_id|ts|ipr_ai|ipr_operator|joker_status|joker_entry_hash)"
        },

        "sign": {
            "alg": "ED25519",
            "key_id": args.key_id,
            "pub_ref": args.pub_ref,
            "sig": sig_b64
        }
    }

    write_json(os.path.join(REPO_ROOT, ev_path_rel), ev)

    head["ts"] = ts
    head["latest"] = {
        "event_id": event_id,
        "path": ev_path_rel,
        "entry_sha256": entry
    }
    write_json(head_path, head)

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
        "entry_sha256": entry,
        "signed": True,
        "joker_c2": {
            "status": joker.get("status"),
            "entry_hash": joker.get("entry_hash")
        }
    }, indent=2))


if __name__ == "__main__":
    main()
