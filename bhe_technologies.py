#!/usr/bin/env python3
"""Print technologies evidenced by the objects in a BloodHound Enterprise graph."""

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


DEFAULT_RULES = {
    "ServiceNow": [r"service[\s_-]*now"],
    "Azure/Entra ID": [r"(?<![a-z0-9])azure(?![a-z])", r"entra[\s_-]*id",
                       r"azure[\s_-]*ad", r"windows[\s_-]*azure"],
    "Veeam": [r"veeam", r"(?<![a-z0-9])veam(?![a-z])"],
    "CrowdStrike": [r"crowd[\s_-]*strike"],
    "Ping Identity": [r"ping[\s_-]*identity", r"ping[\s_-]*federate",
                      r"ping[\s_-]*access", r"ping[\s_-]*one", r"ping[\s_-]*directory"],
    "XSOAR": [r"xsoar", r"demisto"],
    "CyberArk": [r"cyber[\s_-]*ark"],
    "Varonis": [r"varonis"],
    "Tanium": [r"tanium"],
    "AWS": [r"(?<![a-z])aws(?![a-z])", r"amazon[\s_-]*web[\s_-]*services",
            r"amazonaws\.com", r"arn:aws(?:-[a-z-]+)?:"],
}
ENDPOINT = "/api/v2/graphs/cypher"


class ScanError(Exception):
    """A failure that prevents a complete scan."""


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def signed_headers(token_id, token_key, body, timestamp=None):
    timestamp = timestamp or datetime.now(timezone.utc).isoformat(timespec="seconds")
    operation = hmac.new(token_key.encode(), ("POST" + ENDPOINT).encode(), hashlib.sha256).digest()
    date_key = hmac.new(operation, timestamp[:13].encode(), hashlib.sha256).digest()
    signature = hmac.new(date_key, body, hashlib.sha256).digest()
    return {
        "Authorization": "bhesignature " + token_id,
        "RequestDate": timestamp,
        "Signature": base64.b64encode(signature).decode("ascii"),
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "bhe-technology-discovery/1.0",
    }


class BloodHoundClient:
    def __init__(self, url, token_id, token_key, timeout=120):
        parts = urlsplit(url)
        if (parts.scheme != "https" or not parts.hostname or parts.username
                or parts.password or parts.path not in ("", "/") or parts.query or parts.fragment):
            raise ScanError("BHE_URL must be an HTTPS origin, e.g. https://tenant.bloodhoundenterprise.io")
        self.url = url.rstrip("/")
        self.token_id = token_id
        self.token_key = token_key
        self.timeout = timeout
        self.opener = build_opener(NoRedirects())

    def query(self, cypher):
        body = json.dumps({"query": cypher, "include_properties": True}).encode("utf-8")
        for attempt in range(4):
            request = Request(self.url + ENDPOINT, data=body, method="POST",
                              headers=signed_headers(self.token_id, self.token_key, body))
            try:
                with self.opener.open(request, timeout=self.timeout) as response:
                    return json.load(response)
            except HTTPError as exc:
                if exc.code in (429, 502, 503, 504) and attempt < 3:
                    retry_after = exc.headers.get("Retry-After", "")
                    delay = min(int(retry_after), 60) if retry_after.isdigit() else 2 ** attempt
                    exc.close()
                    time.sleep(delay)
                    continue
                status = exc.code
                exc.close()
                hint = {
                    401: "Check the API token ID/key and your system clock.",
                    403: "The API token needs permission to run Cypher queries.",
                    400: "The server rejected the Cypher query; check version compatibility.",
                    301: "Set BHE_URL to the final HTTPS origin.",
                    302: "Set BHE_URL to the final HTTPS origin.",
                }.get(status, "The scan could not complete.")
                raise ScanError(f"BloodHound returned HTTP {status}. {hint}") from None
            except (URLError, TimeoutError, OSError) as exc:
                raise ScanError(f"Could not reach BloodHound: {exc}") from None
            except (ValueError, UnicodeError):
                raise ScanError("BloodHound returned invalid JSON.") from None

    def objects(self, page_size=500):
        # Keyset pagination also handles a server returning fewer nodes than LIMIT.
        cursor = -1
        while True:
            payload = self.query(
                f"MATCH (n) WHERE id(n) > {cursor} RETURN n ORDER BY id(n) LIMIT {page_size}"
            )
            if not isinstance(payload, dict) or not isinstance(payload.get("data"), dict):
                raise ScanError("Unexpected Cypher response: missing data object.")
            nodes = payload["data"].get("nodes")
            if not isinstance(nodes, dict):
                raise ScanError("Unexpected Cypher response: missing nodes map.")
            if not nodes:
                return
            try:
                ordered = sorted((int(node_id), node) for node_id, node in nodes.items())
            except (ValueError, TypeError):
                raise ScanError("Unexpected Cypher response: node IDs must be integers.") from None
            for node_id, node in ordered:
                if node_id <= cursor:
                    raise ScanError("BloodHound pagination did not advance; scan is incomplete.")
                if not isinstance(node, dict) or not isinstance(node.get("properties"), dict):
                    raise ScanError("Node properties missing despite include_properties=true.")
                yield node
            cursor = ordered[-1][0]


def string_values(value):
    """Search each property value independently, excluding property keys."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from string_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from string_values(item)


def load_rules(path=None):
    rules = dict(DEFAULT_RULES)
    if path:
        with open(path, encoding="utf-8") as handle:
            custom = json.load(handle)
        if not isinstance(custom, dict):
            raise ScanError("Rules must be a JSON object mapping technology names to regex lists.")
        rules.update(custom)
    compiled = {}
    for name, patterns in rules.items():
        if (not isinstance(name, str) or not name or "\n" in name or "\r" in name
                or not isinstance(patterns, list) or not all(isinstance(p, str) for p in patterns)):
            raise ScanError("Each rule must have a nonempty name and a list of regex strings.")
        compiled[name] = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
    return compiled


def detect_technologies(objects, rules):
    found = set()
    for node in objects:
        values = list(string_values(node.get("properties", {})))
        values.extend(string_values(node.get("label", "")))
        kinds = list(string_values(node.get("kinds", [])))
        kinds.extend(string_values(node.get("kind", "")))
        values.extend(kinds)
        # AZ node kinds evidence collected Azure/Entra objects even with generic names.
        if "Azure/Entra ID" in rules and rules["Azure/Entra ID"] and any(
                re.match(r"^AZ[A-Z]", kind) for kind in kinds):
            found.add("Azure/Entra ID")
        if "AWS" in rules and rules["AWS"] and any(kind.startswith("AWS") for kind in kinds):
            found.add("AWS")
        for name, patterns in rules.items():
            if name not in found and any(pattern.search(value) for pattern in patterns for value in values):
                found.add(name)
    return sorted(found, key=str.casefold)


def positive_int(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=os.getenv("BHE_URL"), help="BloodHound HTTPS origin (or BHE_URL)")
    parser.add_argument("--page-size", type=positive_int, default=500)
    parser.add_argument("--timeout", type=positive_int, default=120, help="Request timeout in seconds")
    parser.add_argument("--rules", help="JSON file extending or overriding default regex rules")
    args = parser.parse_args(argv)
    token_id, token_key = os.getenv("BHE_TOKEN_ID"), os.getenv("BHE_TOKEN_KEY")
    if not args.url or not token_id or not token_key:
        parser.error("Set BHE_URL (or --url), BHE_TOKEN_ID, and BHE_TOKEN_KEY.")
    try:
        rules = load_rules(args.rules)
        client = BloodHoundClient(args.url, token_id, token_key, args.timeout)
        found = detect_technologies(client.objects(args.page_size), rules)
    except (ScanError, OSError, ValueError, re.error) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Scan interrupted.", file=sys.stderr)
        return 130
    # Print only after the full scan succeeds, avoiding a misleading partial inventory.
    for name in found:
        print(name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
