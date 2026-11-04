"""Read fixed account endpoints and emit only whitelisted, nonsecret status."""
import json
import hashlib
import os
import urllib.error
import urllib.request

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

opener = urllib.request.build_opener(NoRedirect())

def read(url, token=None, method="GET", payload=None):
    if not url.startswith(("https://speedbot.dev/", "https://gofrantic.com/", "https://market.near.ai/")):
        raise ValueError("Unapproved destination")
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, headers=headers, method=method,
                                data=json.dumps(payload).encode() if payload is not None else None)
    try:
        with opener.open(req, timeout=25) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        return exc.code, {}

result = {"worker_version": 1, "mutations_performed": 0, "secrets_printed": False}
near_only = os.environ.get("VERIFY_NEAR_ONLY") == "true"
for service in ("speedbot", "frantic"):
    if near_only:
        result[service] = {"state": "skipped_scoped_near_validation", "api_calls": 0}
        continue
    if service == "frantic" and not os.environ.get("FRANTIC_AGENT_TOKEN"):
        result[service] = {"state": "parked_no_active_work", "api_calls": 0}
        continue
    try:
        if service == "speedbot":
            key = os.environ.get("SPEEDBOT_AGENT_KEY")
            if not key:
                raise RuntimeError("Required secret absent")
            status, data = read("https://speedbot.dev/api/product-projects/api_mine", key, "POST", {})
            products = data.get("products", [])
            own = [p for p in products if p.get("product_id") == "product_587cd29285e440e4a440b2e188c164d7"]
            result[service] = {
                "http": status, "authenticated_owned_listing_read": status == 200 and len(own) == 1,
                "listing_count": len(products),
                "paid_calls": own[0].get("paid_call_count", 0) if own else None,
                "quality_state": own[0].get("quality_review_status", {}).get("state") if own else None,
            }
        else:
            key = os.environ.get("FRANTIC_AGENT_TOKEN")
            if not key:
                raise RuntimeError("Required secret absent")
            status, private = read("https://gofrantic.com/v1/bounties/130", key)
            anonymous_status, anonymous = read("https://gofrantic.com/v1/bounties/130")
            party_access = (status == 200 and bool(private.get("bounty", {}).get("description"))
                            and anonymous_status == 200
                            and not anonymous.get("bounty", {}).get("description"))
            status, data = read("https://gofrantic.com/v1/agents/agent-0c79e4/status", key)
            summary = data.get("work", {}).get("summary", {})
            result[service] = {
                "http": status, "authenticated_private_read": party_access,
                "active_claims": summary.get("active"),
                "awaiting_payout": summary.get("acceptedAwaitingPayout"),
                "paid_recent": summary.get("paidRecent"),
            }
    except Exception as exc:
        result[service] = {"error_type": type(exc).__name__}
if near_only:
    try:
        key = os.environ.get("NEAR_AGENT_TOKEN")
        if not key:
            raise RuntimeError("Required agent secret absent")
        bids_http, bids_data = read("https://market.near.ai/v1/agents/me/bids?live=true", key)
        assignments_http, assignments_data = read("https://market.near.ai/v1/agents/me/assignments", key)
        bids = bids_data.get("bids", [])
        assignments = assignments_data.get("assignments", [])
        identifiers = {str(row.get("bidId", row.get("id", ""))) for row in bids}
        identifiers.update(str(row.get("bidId", "")) for row in assignments)
        observed = {hashlib.sha256(value.encode()).hexdigest() for value in identifiers if value}
        expected = {'e15294e559a4f81bd519406d26999211a85071348a5342305a1cd43002e5938c', 'c4081c262bbf27b80b656f2b2178e4b054054cb18ca6bf5a9699bfe3656b1884'}
        result["near"] = {
            "bids_http": bids_http,
            "assignments_http": assignments_http,
            "expected_owned_bids_match": expected.issubset(observed),
            "bid_count": len(bids),
            "pending_bid_count": sum(row.get("status") == "pending" for row in bids),
            "assignment_count": len(assignments),
            "buyer_content_printed": False,
        }
        result["ok"] = bids_http == assignments_http == 200 and expected.issubset(observed)
    except Exception as exc:
        result["near"] = {"error_type": type(exc).__name__}
        result["ok"] = False
else:
    result["near"] = {"state": "passive_no_api_calls", "api_calls": 0}
    result["ok"] = (result.get("speedbot", {}).get("authenticated_owned_listing_read") is True
                    and (result.get("frantic", {}).get("authenticated_private_read") is True
                         or result.get("frantic", {}).get("state") == "parked_no_active_work"))
rendered = json.dumps(result, indent=2)
print(rendered)
if os.environ.get("GITHUB_STEP_SUMMARY"):
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as handle:
        handle.write("## Cloud account checkpoint\n\n\x60\x60\x60json\n" + rendered + "\n\x60\x60\x60\n")
raise SystemExit(0 if result["ok"] else 1)
