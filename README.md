# BloodHound technology discovery

`bhe_technologies.py` scans every graph node visible to your BloodHound Enterprise
API token and prints each detected technology once, sorted alphabetically.
Requires Python 3.9 or newer; there are no third-party dependencies.

## Run

Create an API token in BloodHound with permission to execute Cypher queries, then
set the credentials locally:

```sh
export BHE_URL='https://your-tenant.bloodhoundenterprise.io'
export BHE_TOKEN_ID='your-token-id'
read -rs 'BHE_TOKEN_KEY?API token key: '
export BHE_TOKEN_KEY
python3 bhe_technologies.py
```

The secret prompt above is for zsh (the default macOS shell). In bash use
`read -rs -p 'API token key: ' BHE_TOKEN_KEY` instead.
Avoid placing the token key in source files or committing it to version control.

Example output (illustrative):

```text
AWS
Azure/Entra ID
CrowdStrike
CyberArk
ServiceNow
Veeam
```

To save the list: `python3 bhe_technologies.py > technologies.txt`.
No matches produces empty output with exit status 0. A failed or interrupted scan
produces an error on stderr and a nonzero exit status, without printing partial results.

## How it works

The program uses signed HMAC authentication and calls
`POST /api/v2/graphs/cypher` with `include_properties: true`. It requests nodes in
ascending graph ID order, continuing after the last ID until an empty page is
returned. It processes batches in memory rather than retaining the full graph.
The default batch size is 500; use `--page-size 100` or `--timeout 180` if needed.
Transient HTTP 429/502/503/504 responses are retried up to three times.
TLS certificates are verified and redirects are rejected.

Detection searches string property values (including nested lists), graph display
labels, and node kinds, case-insensitively. This covers names, descriptions,
service principal names, and application URLs when those fields are collected.
Defaults cover ServiceNow, Azure/Entra ID, Veeam (also the spelling Veam),
CrowdStrike, Ping Identity, XSOAR/Demisto, CyberArk, Varonis, Tanium, and AWS.
Azure `AZ…` node kinds and AWS-prefixed node kinds also count as platform evidence.
Generic words such as `ping` and `falcon` alone do not trigger matches.

These are heuristic indicators from collected identity data, not proof of an
active installation or a complete software inventory. References to retired
applications can match; unnamed products and uncollected fields cannot. Changes
to the graph during pagination can affect coverage; run against stable collected
data when completeness matters. The server must support `id(n)`, `ORDER BY`,
`LIMIT`, and returning node properties through the Cypher endpoint.

## Customize detection

Pass `--rules rules.json` to extend or replace the patterns for named technologies:

```json
{
  "CrowdStrike": ["crowd[\\s_-]*strike", "(?<![a-z0-9])csagent(?![a-z])"],
  "Okta": ["okta"],
  "Varonis": []
}
```

Rules are Python regular expressions. An empty list disables that technology,
including automatic node-kind detection. Replacing a rule replaces its whole
pattern list. Add local abbreviations only when they identify the product reliably.

## Verification and API references

Run the offline tests with `python3 -m unittest discover -s tests -v`.
Live tenant access is required to validate your server version and collected data.

- [SpecterOps API authentication specification](https://github.com/SpecterOps/BloodHound/blob/main/packages/go/openapi/src/openapi.yaml)
- [Cypher endpoint specification](https://github.com/SpecterOps/BloodHound/blob/main/packages/go/openapi/src/paths/cypher.graphs.cypher.yaml)
- [Returned node schema](https://github.com/SpecterOps/BloodHound/blob/main/packages/go/openapi/src/schemas/model.unified-graph.node.yaml)
