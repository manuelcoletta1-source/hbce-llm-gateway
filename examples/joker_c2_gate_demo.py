import os
import sys
import json

# Ensure repo root is importable when running from /examples
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from joker_c2_governor import joker_c2_gate, FailClosed  # noqa: E402


CORE_DIR = os.environ.get("JOKER_C2_CORE_DIR", "/home/manuelcoletta1/hbce-joker-c2-core")
OUT_DIR = os.environ.get("JOKER_C2_OUT_DIR", "/home/manuelcoletta1/hbce-joker-c2-core/out")


def load_req(p: str):
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


def main():
    # Use canonical examples from hbce-joker-c2-core to avoid schema drift.
    allow_path = os.path.join(CORE_DIR, "examples", "request.allow.sample.json")
    deny_path = os.path.join(CORE_DIR, "examples", "request.deny.sample.json")

    # PASS
    req_allow = load_req(allow_path)
    req_allow["request_id"] = "GATEWAY-DEMO-ALLOW-0001"

    res_allow = joker_c2_gate(
        req_allow,
        joker_c2_core_dir=CORE_DIR,
        out_dir=OUT_DIR,
    )
    print("ALLOW_DECISION:", res_allow.status, res_allow.entry_hash)

    # DENY
    req_deny = load_req(deny_path)
    req_deny["request_id"] = "GATEWAY-DEMO-DENY-0001"

    res_deny = joker_c2_gate(
        req_deny,
        joker_c2_core_dir=CORE_DIR,
        out_dir=OUT_DIR,
    )
    print("DENY_DECISION:", res_deny.status, res_deny.entry_hash)

    # Fail-closed enforcement example:
    if res_deny.status != "PASS":
        print("FAIL_CLOSED: downstream LLM call MUST NOT execute for DENY.")


if __name__ == "__main__":
    try:
        main()
    except FailClosed as e:
        print("FAIL_CLOSED:", str(e))
        raise
