"""Replay a seed's setup calls against an UNPATCHED emulator (started with `-a off`).

    python dry_run_setup.py seed.json https://127.0.0.1:9412 CA.pem

A smoke test for the request shapes a seed carries, usable without the patched binary:
captures and tokens work as in the patch; pinned ids are not pinned, so every pinned id is
mapped to the id the emulator really minted and rewritten in later requests. Prints one line
per failing call and exits non-zero if any failed.
"""

from __future__ import annotations

import json
import re
import ssl
import sys
import urllib.error
import urllib.request

PATTERNS = {
    "i": r"\bi-[0-9a-f]{17}\b", "r": r"\br-[0-9a-f]{17}\b",
    "elbv2": r"/([0-9a-f]{16})(?=<|\"|$|/)", "Z": r"/hostedzone/(Z[A-Z0-9]+)",
    "C": r"/change/(C[A-Z0-9]+)", "dbi": r"\bdb-[A-Z0-9]{26}\b",
    "rdshost": r"\.([a-z0-9]{12})\.[a-z0-9-]+\.rds\.amazonaws\.com",
    "AROA": r"\bAROA[A-Z0-9]{17}\b", "ANPA": r"\bANPA[A-Z0-9]{17}\b", "AIPA": r"\bAIPA[A-Z0-9]{17}\b",
}


def pattern(kind: str) -> str:
    return PATTERNS.get(kind, rf"\b{re.escape(kind)}-[0-9a-f]{{8,17}}\b")


def find_field(body: str, field: str, index: int = 0):
    found = re.findall(rf"<{field}>(.*?)</{field}>", body, re.S)
    if not found:  # EC2 answers in lowerCamel (<vpcId>)
        lower = field[:1].lower() + field[1:]
        found = re.findall(rf"<{lower}>(.*?)</{lower}>", body, re.S)
    if not found:
        found = re.findall(rf'"{field}"\s*:\s*"((?:[^"\\]|\\.)*)"', body)
    return found[index] if len(found) > index else None


def main() -> int:
    seed_path, endpoint, ca = sys.argv[1:4]
    seed = json.load(open(seed_path))
    ctx = ssl.create_default_context(cafile=ca)
    captures: dict[str, str] = {}
    rewrite: dict[str, str] = {}
    failed = 0

    def fill(text: str) -> str:
        text = re.sub(r"ocwref__([a-z0-9]+)__", lambda m: captures.get(m.group(1), m.group(0)), text)
        for pinned, real in rewrite.items():
            text = text.replace(pinned, real)
        return text

    seen_before: set[str] = set()
    for index, call in enumerate(seed["setup"]):
        req = call["request"]
        url = endpoint + fill(req["path"]) + (("?" + fill(req["query"])) if req.get("query") else "")
        body = fill(req.get("body") or "").encode()
        headers = {k: fill(v) for k, v in req["headers"].items() if k.lower() not in ("host",)}
        r = urllib.request.Request(url, data=body if req["method"] != "GET" else None,
                                   headers=headers, method=req["method"])
        try:
            with urllib.request.urlopen(r, context=ctx) as resp:
                status, text = resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            status, text = e.code, e.read().decode("utf-8", "replace")
        ok = 200 <= status < 300
        code = find_field(text, "Code") or find_field(text, "__type") or ""
        if not ok and call.get("expect_error") != code.split("#")[-1]:
            failed += 1
            print(f"FAIL setup[{index}] {call['service']}.{call['operation']}: {status} {text[:300]}")
            continue
        for kind, ids in (call.get("ids") or {}).items():
            minted = [m if isinstance(m, str) else m for m in re.findall(pattern(kind), text)]
            minted = [m for m in dict.fromkeys(minted) if m not in seen_before]
            for pinned, real in zip(ids, minted):
                rewrite[pinned] = real
        for m in re.findall(r"[A-Za-z0-9-]{8,}", text):
            seen_before.add(m)
        for name, how in (call.get("capture") or {}).items():
            field, strip, nth = (how, None, 0) if isinstance(how, str) else (
                how["field"], how.get("strip_prefix"), how.get("index", 0))
            value = find_field(text, field, nth)
            if value is None:
                failed += 1
                print(f"FAIL setup[{index}] capture {name}: no {field}: {text[:200]}")
                continue
            if strip and value.startswith(strip):
                value = value[len(strip):]
            captures[name] = value
    print(f"{len(seed['setup']) - failed}/{len(seed['setup'])} setup calls ok; "
          f"{len(rewrite)} pinned ids mapped")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
