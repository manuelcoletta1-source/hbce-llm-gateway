import os
import json
import tempfile
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple


class FailClosed(Exception):
    """Fail-closed execution: any anomaly blocks the action."""
    pass


@dataclass
class JokerC2Decision:
    status: str  # "PASS" | "DENY"
    entry_hash: str
    stdout: str


def _run(cmd: list[str], env: dict[str, str], cwd: Optional[str] = None) -> Tuple[int, str, str]:
    p = subprocess.run(cmd, env=env, cwd=cwd, capture_output=True, text=True)
    return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()


def joker_c2_gate(
    request_obj: Dict[str, Any],
    *,
    joker_c2_core_dir: str,
    node_bin: str = "node",
    out_dir: Optional[str] = None,
    private_key_pem_path: Optional[str] = None,
) -> JokerC2Decision:
    """
    Joker-C2 fail-closed gate.

    - Writes request JSON to a temp file (stable + deterministic).
    - Calls hbce-joker-c2-core cli.js.
    - Expects:
        PASS entry_hash=<64hex>
      or
        DENY entry_hash=<64hex>
    - Any anomaly => raises FailClosed.
    """
    core_dir = os.path.abspath(joker_c2_core_dir)
    cli_js = os.path.join(core_dir, "cli.js")
    if not os.path.exists(cli_js):
        raise FailClosed(f"JOKER_C2_CORE_NOT_FOUND: {cli_js}")

    env = dict(os.environ)

    # Load signing key (same pattern you used on Linux quickstart).
    if private_key_pem_path:
        pk = os.path.abspath(private_key_pem_path)
        if not os.path.exists(pk):
            raise FailClosed("MISSING_ED25519_PRIVATE_KEY_PEM_PATH")
        with open(pk, "r", encoding="utf-8") as f:
            env["HBCE_ED25519_PRIVATE_KEY_PEM"] = f.read()
    else:
        if not env.get("HBCE_ED25519_PRIVATE_KEY_PEM"):
            raise FailClosed("MISSING_ED25519_PRIVATE_KEY_PEM")

    # Create deterministic request file
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json", encoding="utf-8") as tf:
        json.dump(request_obj, tf, indent=2, sort_keys=True)
        tf.write("\n")
        req_path = tf.name

    try:
        cmd = [node_bin, cli_js, req_path]
        if out_dir:
            cmd += ["--out", os.path.abspath(out_dir)]

        code, out, err = _run(cmd, env=env, cwd=core_dir)

        # cli.js prints PASS/DENY to stdout on success
        if out.startswith("PASS entry_hash="):
            entry_hash = out.split("PASS entry_hash=", 1)[1].strip()
            return JokerC2Decision(status="PASS", entry_hash=entry_hash, stdout=out)

        if out.startswith("DENY entry_hash="):
            entry_hash = out.split("DENY entry_hash=", 1)[1].strip()
            return JokerC2Decision(status="DENY", entry_hash=entry_hash, stdout=out)

        # Fail-closed: if CLI returned something else, block.
        raise FailClosed(f"JOKER_C2_UNEXPECTED_OUTPUT code={code} stdout={out} stderr={err}")

    finally:
        try:
            os.unlink(req_path)
        except Exception:
            pass
