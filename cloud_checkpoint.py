"""Read fixed account endpoints and emit only whitelisted, nonsecret status."""
import json
import os
import urllib.error
import urllib.request

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

opener = urllib.request.build_opener(NoRedirect())

def read(url, token=None, method="GET", payload=None):
    if not url.startswith(("https://speedbot.dev/", "https://gofrantic.com/")):
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
for service in ("speedbot", "frantic"):
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
result["ok"] = (result.get("speedbot", {}).get("authenticated_owned_listing_read") is True
                and (result.get("frantic", {}).get("authenticated_private_read") is True
                     or result.get("frantic", {}).get("state") == "parked_no_active_work"))
rendered = json.dumps(result, indent=2)
print(rendered)
if os.environ.get("GITHUB_STEP_SUMMARY"):
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as handle:
        handle.write("## Cloud account checkpoint\n\n\x60\x60\x60json\n" + rendered + "\n\x60\x60\x60\n")
raise SystemExit(0 if result["ok"] else 1)
