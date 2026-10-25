"""Reject empty, skipped or partial protocol runs."""
import json
import pathlib
import sys

root = "TestTLSProxyProtocolWireOrder"
events = [json.loads(line) for line in pathlib.Path(sys.argv[1]).read_text().splitlines() if line.startswith("{")]
terminal = {event["Test"]: event["Action"] for event in events if event.get("Test", "").startswith(root + "/") and event.get("Action") in {"pass", "fail", "skip"}}
assert len(terminal) == 6, terminal
assert all(action == "pass" for action in terminal.values()), terminal
assert any(event.get("Test") == root and event.get("Action") == "pass" for event in events)
receipt = json.loads(pathlib.Path(sys.argv[1]).with_name("results.json").read_text())
assert receipt["schema"] == "traefik-12100-wire-order/v1"
assert receipt["status"] == "PASS" and receipt["observed_cases"] == receipt["passed_cases"] == 6
rows = receipt["results"]
expected = {(mode, version) for mode in ["envoy_default_pre_tls", "envoy_counterfactual_post_tls", "ordinary_pre_tls"] for version in [1, 2]}
assert len(rows) == 6 and {(r["mode"], r["version"]) for r in rows} == expected
for row in rows:
    assert row["passed"]
    negative = row["mode"] == "envoy_default_pre_tls"
    counterfactual = row["mode"] == "envoy_counterfactual_post_tls"
    assert row["actual_traefik_proxy_enabled"] is not counterfactual
    assert row["manual_post_tls_header"] is counterfactual
    assert row["expected_tls_handshake_error"] is negative
    if negative:
        error = row.get("error", "")
        assert "TLS handshake failed" in error
        assert not any(word in error.lower() for word in ["timeout", "deadline"]), error
    else:
        assert row["proxy_version"] == row["version"]
        assert row["source"] == "198.51.100.23:53124"
        assert row["destination"] == "203.0.113.7:443"
        assert row["reply"] == "PONG"
summary = {"observed_subtests": len(terminal), "results": terminal, "all_expected_observations_passed": True, "upstream_fix_or_acceptance": False}
pathlib.Path(sys.argv[1]).with_name("checked-results.json").write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary))
