"""Build `ocw-aws-seed/1` files: the reference serializer for setup calls.

`SeedBuilder.call(service, operation, params, at=..., capture=..., ids=...)` serializes the
call exactly as botocore (and so the AWS CLI) would send it, and records the wire request.
Parameters may hold `ref("name")` tokens, which the emulator fills from earlier captures.

    seed = SeedBuilder(account_id="418295736104", now=1773932400.0)
    seed.call("ec2", "CreateVpc", {"CidrBlock": "10.40.0.0/16"}, at=..., capture={"vpc": "VpcId"},
              ids={"vpc": ["vpc-0a1b2c3d4e5f60718"]})
    seed.call("ec2", "CreateSubnet", {"VpcId": ref("vpc"), ...})
    seed.data["metrics"].append({...})
    seed.write("seed.json")

Only botocore is needed (`pip install botocore`).
"""

from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any

import botocore.config
import botocore.session

FORMAT = "ocw-aws-seed/1"
_ENDPOINT = "https://localhost"


def ref(name: str) -> str:
    """A token the emulator replaces with an earlier capture (`name` is [a-z0-9]+)."""
    if not re.fullmatch(r"[a-z0-9]+", name):
        raise ValueError(f"capture names are [a-z0-9]+: {name!r}")
    return f"ocwref__{name}__"


class _Captured(Exception):
    pass


class SeedBuilder:
    def __init__(self, *, account_id: str, now: float, region: str = "us-east-1") -> None:
        self.account_id = account_id
        self.region = region
        self.now = now
        self.setup: list[dict] = []
        self.data: dict[str, Any] = {
            "metrics": [], "alarms": [], "target_health": [], "cloudtrail": [], "logs": [],
            "rds_events": [], "elasticache_events": [], "autoscaling_activities": [],
            "instance_status": [], "instance_states": [],
        }
        self.read_only: dict[str, Any] = {}
        self._session = botocore.session.get_session()
        self._clients: dict[str, Any] = {}

    def _client(self, service: str):
        client = self._clients.get(service)
        if client is None:
            client = self._session.create_client(
                service, region_name=self.region, endpoint_url=_ENDPOINT,
                aws_access_key_id="AKIAOCWSEEDROOT00000", aws_secret_access_key="seed",
                config=botocore.config.Config(
                    inject_host_prefix=False, retries={"max_attempts": 1},
                    parameter_validation=False,
                    s3={"addressing_style": "path"},
                    request_checksum_calculation="when_required",
                    response_checksum_validation="when_required"))
            captured: dict[str, Any] = {}

            def grab(request, **_kw):
                captured["request"] = request
                raise _Captured()

            client.meta.events.register("before-send", grab)
            client._ocw_captured = captured
            self._clients[service] = client
        return client

    def wire(self, service: str, operation: str, params: dict) -> dict:
        """The request botocore sends for this call, as the seed carries it."""
        client = self._client(service)
        method = client.meta.method_to_api_mapping
        api_to_method = {v: k for k, v in method.items()}
        try:
            getattr(client, api_to_method[operation])(**params)
        except _Captured:
            pass
        request = client._ocw_captured.pop("request")
        url = urllib.parse.urlsplit(request.url)
        body = request.body
        if body is None:
            body = ""
        elif isinstance(body, bytes):
            body = body.decode("utf-8")
        elif not isinstance(body, str):
            body = body.read().decode("utf-8")
        headers = {k: (v.decode() if isinstance(v, bytes) else str(v))
                   for k, v in request.headers.items()
                   if k.lower() not in ("content-length", "amz-sdk-invocation-id",
                                        "amz-sdk-request")}
        return {"method": request.method, "path": url.path or "/", "query": url.query,
                "headers": headers, "body": body}

    def call(self, service: str, operation: str, params: dict, *, at: float | None = None,
             capture: dict | None = None, ids: dict[str, list[str]] | None = None,
             expect_error: str | None = None) -> None:
        entry: dict[str, Any] = {
            "at": self.now if at is None else at, "service": service, "operation": operation,
            "request": self.wire(service, operation, params), "params": params}
        if capture:
            entry["capture"] = capture
        if ids:
            entry["ids"] = ids
        if expect_error:
            entry["expect_error"] = expect_error
        self.setup.append(entry)

    def to_dict(self) -> dict:
        out = {"format": FORMAT, "account_id": self.account_id, "region": self.region,
               "clock": {"now": self.now}, "setup": self.setup}
        out.update({k: v for k, v in self.data.items() if v})
        if self.read_only:
            out["read_only"] = self.read_only
        return out

    def write(self, path: str) -> None:
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, default=str)
