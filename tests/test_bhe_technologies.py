import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch
from urllib.error import HTTPError

import bhe_technologies as bhe


def node(name="", **properties):
    return {"label": name, "kind": "User", "properties": properties}


class DetectionTests(unittest.TestCase):
    def test_all_requested_products_and_aliases(self):
        names = ["svc_ServiceNow", "Azure AD Connect", "VEEAM01.corp.local",
                 "CrowdStrike Falcon", "PingFederate", "Demisto automation",
                 "CyberArk Vault", "Varonis service", "Tanium client",
                 "https://signin.aws.amazon.com"]
        result = bhe.detect_technologies((node(name) for name in names), bhe.load_rules())
        self.assertEqual(set(result), set(bhe.DEFAULT_RULES))
        self.assertEqual(result, sorted(result, key=str.casefold))

    def test_nested_properties_duplicates_and_word_boundaries(self):
        nodes = [node(description=[{"value": "svc_crowdstrike@corp"}]),
                 node("CROWDSTRIKE01"), node("ping server"), node("falcon team"),
                 node("drawstring"), node(aws_enabled=True)]
        self.assertEqual(bhe.detect_technologies(nodes, bhe.load_rules()), ["CrowdStrike"])

    def test_platform_kinds(self):
        nodes = [{"kinds": ["AZTenant"], "properties": {"name": "CORP"}},
                 {"kind": "AWSRole", "properties": {"name": "Admin"}}]
        self.assertEqual(bhe.detect_technologies(nodes, bhe.load_rules()), ["AWS", "Azure/Entra ID"])

    def test_custom_rules_and_disabled_platform(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as file:
            json.dump({"Okta": ["okta"], "Azure/Entra ID": []}, file)
            file.flush()
            rules = bhe.load_rules(file.name)
        nodes = [node("Okta SSO"), {"kind": "AZUser", "properties": {}}]
        self.assertEqual(bhe.detect_technologies(nodes, rules), ["Okta"])


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.client = bhe.BloodHoundClient("https://tenant.bloodhoundenterprise.io", "id", "key")

    def test_signature_vector_and_body_integrity(self):
        headers = bhe.signed_headers("test-id", "test-key", b'{"query":"MATCH (n) RETURN n"}',
                                     "2026-10-01T12:34:56+00:00")
        self.assertEqual(headers["Authorization"], "bhesignature test-id")
        self.assertEqual(headers["Signature"], "BMTnQwJ3SP0y0ZzUvf8ja0n7npktA31BBkTNiVPP/u0=")
        changed = bhe.signed_headers("test-id", "test-key", b"changed", headers["RequestDate"])
        self.assertNotEqual(headers["Signature"], changed["Signature"])

    def test_pagination_continues_after_short_page_and_sorts_ids(self):
        pages = [{"data": {"nodes": {"12": node("Veeam"), "2": node("Tanium")}}},
                 {"data": {"nodes": {"35": node("AWS")}}},
                 {"data": {"nodes": {}}}]
        with patch.object(self.client, "query", side_effect=pages) as query:
            result = list(self.client.objects(500))
        self.assertEqual([n["label"] for n in result], ["Tanium", "Veeam", "AWS"])
        self.assertEqual(query.call_args_list[1].args[0],
                         "MATCH (n) WHERE id(n) > 12 RETURN n ORDER BY id(n) LIMIT 500")
        self.assertIn("id(n) > 35", query.call_args_list[2].args[0])

    def test_malformed_responses_and_stalled_pagination_fail(self):
        for payload in [{}, {"data": {}}, {"data": {"nodes": []}},
                        {"data": {"nodes": {"x": node()}}},
                        {"data": {"nodes": {"1": {"label": "ServiceNow"}}}}]:
            with self.subTest(payload=payload), patch.object(self.client, "query", return_value=payload):
                with self.assertRaises(bhe.ScanError):
                    list(self.client.objects())
        repeated = {"data": {"nodes": {"1": node()}}}
        with patch.object(self.client, "query", return_value=repeated):
            with self.assertRaisesRegex(bhe.ScanError, "did not advance"):
                list(self.client.objects())

    def test_request_body_properties_and_retry(self):
        response = io.BytesIO(b'{"data":{"nodes":{}}}')
        error = HTTPError(self.client.url, 429, "Rate limited", {"Retry-After": "0"}, io.BytesIO())
        with patch.object(self.client.opener, "open", side_effect=[error, response]) as request, \
                patch.object(bhe.time, "sleep"):
            self.assertEqual(self.client.query("MATCH (n) RETURN n"), {"data": {"nodes": {}}})
        sent = request.call_args.args[0]
        self.assertEqual(json.loads(sent.data), {"query": "MATCH (n) RETURN n", "include_properties": True})
        self.assertEqual(sent.full_url, self.client.url + bhe.ENDPOINT)
        self.assertEqual(request.call_count, 2)

    def test_https_origin_validation(self):
        for url in ["http://tenant.example", "https://tenant.example/api", "https://a:b@tenant.example",
                    "https://tenant.example?query=1", "https://tenant.example#fragment"]:
            with self.subTest(url=url), self.assertRaises(bhe.ScanError):
                bhe.BloodHoundClient(url, "id", "key")

    def test_auth_failure_does_not_retry(self):
        error = HTTPError(self.client.url, 401, "Unauthorized", {}, io.BytesIO())
        with patch.object(self.client.opener, "open", side_effect=error) as request:
            with self.assertRaisesRegex(bhe.ScanError, "401"):
                self.client.query("MATCH (n) RETURN n")
        self.assertEqual(request.call_count, 1)


class CommandTests(unittest.TestCase):
    def run_main(self, side_effect):
        stdout, stderr = io.StringIO(), io.StringIO()
        credentials = {"BHE_URL": "https://tenant.example", "BHE_TOKEN_ID": "id", "BHE_TOKEN_KEY": "key"}
        with patch.dict(os.environ, credentials), patch.object(bhe.BloodHoundClient, "objects", side_effect=side_effect), \
                redirect_stdout(stdout), redirect_stderr(stderr):
            status = bhe.main([])
        return status, stdout.getvalue(), stderr.getvalue()

    def test_stdout_is_only_unique_names(self):
        status, stdout, stderr = self.run_main(lambda _: iter([node("Tanium"), node("AWS"), node("AWS")]))
        self.assertEqual((status, stdout, stderr), (0, "AWS\nTanium\n", ""))

    def test_no_partial_output_on_failure(self):
        def objects(_):
            yield node("ServiceNow")
            raise bhe.ScanError("request failed")
        status, stdout, stderr = self.run_main(objects)
        self.assertEqual((status, stdout), (1, ""))
        self.assertIn("request failed", stderr)

    def test_no_matches_is_successful_empty_output(self):
        self.assertEqual(self.run_main(lambda _: iter([node("Admin")])), (0, "", ""))


if __name__ == "__main__":
    unittest.main()
