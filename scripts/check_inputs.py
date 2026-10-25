"""Bind the loaded transport source and copied module to the recorded input bytes."""
import hashlib
import json
import pathlib
import subprocess

root = pathlib.Path(__file__).resolve().parents[1]
inputs = json.loads((root / "provenance.json").read_text())
for item in inputs["source"]["copied_nested_module"]:
    raw = (root / item["local_file"]).read_bytes()
    assert len(raw) == item["bytes"] and hashlib.sha256(raw).hexdigest() == item["sha256"]
package = "github.com/traefik/traefik/v3/pkg/tcp"
loaded = json.loads(subprocess.check_output(["go", "list", "-json", package], text=True))
assert loaded["Module"]["Version"] == inputs["source"]["go_module"]
digest = hashlib.sha256((pathlib.Path(loaded["Dir"]) / "dialer.go").read_bytes()).hexdigest()
assert digest == inputs["source"]["dialer_file_sha256"]
receipt = {"loaded_module": loaded["Module"], "transport_package": package, "dialer_sha256": digest, "copied_nested_module_matches": True}
out = root / "evidence"
out.mkdir(exist_ok=True)
(out / "inputs-checked.json").write_text(json.dumps(receipt, indent=2) + "\n")
print(json.dumps(receipt))
