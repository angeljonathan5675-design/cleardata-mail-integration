"""Capture tests and explicitly authorized one-message delivery."""
import email
import hashlib
import json
import os
import pathlib
import platform
import re
import smtplib
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request

import boto3
from botocore.config import Config
import tomllib

stage = "initialization"
started = time.monotonic()
dry_config = "--validate-proof-config" in sys.argv[2:]
proof = "--send-one-proof" in sys.argv[2:] or dry_config
if proof and not dry_config and (os.environ.get("CLEARDATA_ONE_PROOF_AUTHORIZED") != "yes" or not os.environ.get("PROOF_REPLY_TO")):
    raise SystemExit("One-message authorization and private reply address are required")
evidence = {"mode": "config_validation" if dry_config else ("delivery" if proof else "capture"), "external_messages_sent": 0}
engine = None

def run(args, cwd, data=None):
    result = subprocess.run(args, cwd=cwd, input=data, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError("CLI operation failed")
    return result.stdout + result.stderr

try:
    stage = "non-root check"
    if os.getuid() == 0:
        raise RuntimeError("Non-root user required")
    binary = str(pathlib.Path(sys.argv[1]).resolve())
    evidence.update(os=platform.system(), architecture=platform.machine(), non_root=True,
                    sdk_version=boto3.__version__)
    evidence["nitromta_version"] = run([binary, "--version"], None).strip()
    if "0.1.6" not in evidence["nitromta_version"]:
        raise RuntimeError("Unexpected engine version")
    with tempfile.TemporaryDirectory(prefix="cleardata-nitromta-") as work:
        work = pathlib.Path(work)
        stage = "capture setup"
        run([binary, "setup", "--config", "config.toml", "--capture"], work)
        if proof:
            lines = (work / "config.toml").read_text().splitlines()
            configured = []
            section = ""
            for line in lines:
                stripped = line.strip()
                if stripped.startswith("[") and stripped.endswith("]"):
                    section = stripped
                    if section == "[capture]":
                        continue
                    configured.append(line)
                    if section == "[delivery]":
                        configured.extend(["port = 2525", "dane = false"])
                    continue
                if section == "[capture]":
                    continue
                if section == "[delivery]" and re.match(r"#?\s*(port|dane)\s*=", stripped):
                    continue
                configured.append(line)
            config_text = "\n".join(configured) + "\n"
            parsed = tomllib.loads(config_text)
            if "capture" in parsed or parsed.get("delivery", {}).get("port") != 2525:
                raise RuntimeError("Proof delivery configuration did not validate")
            (work / "config.toml").write_text(config_text)
            if dry_config:
                evidence.update(ok=True, proof_config_valid=True, configured_port=2525,
                                capture_disabled=True, dane_for_test_resolver=False)
                raise SystemExit(0)
        engine = subprocess.Popen([binary, "run", "--config", "config.toml"],
                                  cwd=work, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        stage = "engine startup"
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if engine.poll() is not None:
                raise RuntimeError("Engine exited during startup")
            try:
                with socket.create_connection(("127.0.0.1", 9090), timeout=1):
                    break
            except OSError:
                time.sleep(0.2)
        else:
            raise TimeoutError("Inspector did not start")
        stage = "identity and credentials"
        private_key = run(["openssl", "genpkey", "-algorithm", "RSA",
                           "-pkeyopt", "rsa_keygen_bits:2048"], work)
        operations = [
            {"op": "put_account", "account": 1},
            {"op": "put_identity", "account": 1, "name": "example.test",
             "selector": "s1", "private_key": private_key},
        ]
        run([binary, "admin", "--config", "config.toml"], work,
            "".join(json.dumps(x) + "\n" for x in operations))
        created = run([binary, "access-key", "create", "--config", "config.toml",
                       "--account", "1"], work)
        match = re.search(r"access key (\S+) created; its secret, shown this once:\s*(\S+)", created)
        if not match:
            raise RuntimeError("Access key output did not match documented format")
        access_id, access_secret = match.groups()
        stage = "TLS-verified local SES submission"
        client = boto3.client("sesv2", endpoint_url="https://127.0.0.1:4443",
                              region_name="us-east-1", aws_access_key_id=access_id,
                              aws_secret_access_key=access_secret, verify=str(work / "tls.crt"),
                              config=Config(retries={"total_max_attempts": 1}, connect_timeout=10, read_timeout=20))
        subject = "ClearData AI NitroMTA delivery test" if proof else "ClearData capture integration"
        message_args = {
            "FromEmailAddress": "app@example.test",
            "Destination": {"ToAddresses": ["proof@nitromta.com" if proof else "receiver@example.test"]},
            "Content": {"Simple": {"Subject": {"Data": subject}, "Body": {"Text": {
                "Data": "One technical email delivery test from ClearData AI. No subscription or response is requested."
                if proof else "A local capture-mode integration test."}}}},
        }
        if proof:
            message_args["ReplyToAddresses"] = [os.environ["PROOF_REPLY_TO"]]
            evidence["external_submission_attempted"] = True
            evidence["external_delivery_state"] = "unknown"
        sent = client.send_email(**message_args)
        evidence["message_id"] = sent["MessageId"]
        if proof:
            stage = "waiting for the original message delivery"
            evidence["external_delivery_state"] = "accepted_by_local_engine"
            deadline = time.monotonic() + 150
            while time.monotonic() < deadline:
                with urllib.request.urlopen("http://127.0.0.1:9090/metrics", timeout=10) as response:
                    metrics = response.read().decode()
                delivered = sum(float(line.rsplit(" ", 1)[-1]) for line in metrics.splitlines()
                                if line.startswith("nitromta_attempts_total{") and 'result="delivered"' in line)
                if delivered >= 1:
                    evidence.update(external_messages_sent=1, external_delivery_state="delivered_by_engine")
                    break
                time.sleep(1)
            else:
                raise TimeoutError("Original message delivery is unresolved; do not submit a new message")
        else:
            stage = "captured output"
            deadline = time.monotonic() + 45
            captured = []
            while time.monotonic() < deadline:
                captured = list(work.rglob("*.eml"))
                if captured:
                    break
                time.sleep(0.2)
            if len(captured) != 1:
                raise RuntimeError("Expected exactly one captured message")
            message = email.message_from_bytes(captured[0].read_bytes())
            if message["Subject"] != subject or not message["DKIM-Signature"]:
                raise RuntimeError("Captured subject or DKIM signature missing")
            evidence.update(captured_messages=1, dkim_signature_present=True, local_tls_verified=True)
            stage = "capture inspector"
            with urllib.request.urlopen("http://127.0.0.1:9090/capture", timeout=10) as response:
                inspector = response.read().decode()
            if subject not in inspector:
                raise RuntimeError("Capture inspector did not show the message")
            evidence["inspector_verified"] = True
        engine.terminate()
        engine.wait(timeout=10)
        engine = None
    stage = "outbound TLS availability probe"
    try:
        with smtplib.SMTP("mta-proof.nitrosend.com", 2525,
                          local_hostname="cleardata-test.invalid", timeout=15) as smtp:
            smtp.ehlo()
            smtp.starttls(context=ssl.create_default_context())
            smtp.ehlo()
        evidence["proof_host_tls_2525"] = "verified_without_sending_mail"
    except Exception as exc:
        evidence["proof_host_tls_2525"] = type(exc).__name__
    evidence.update(ok=True, elapsed_seconds=round(time.monotonic() - started, 2))
except Exception as exc:
    evidence.update(ok=False, failed_stage=stage, error_type=type(exc).__name__,
                    elapsed_seconds=round(time.monotonic() - started, 2))
finally:
    if engine is not None:
        engine.terminate()
        try:
            engine.wait(timeout=10)
        except subprocess.TimeoutExpired:
            engine.kill()
            engine.wait(timeout=10)
    rendered = json.dumps(evidence, indent=2)
    print(rendered)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write("## NitroMTA capture-mode integration\n\n\x60\x60\x60json\n" + rendered + "\n\x60\x60\x60\n")
sys.exit(0 if evidence.get("ok") else 1)
