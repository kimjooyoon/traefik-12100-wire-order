# Traefik #12100: PROXY header inside an Envoy TLS tunnel

This bounded experiment answers the wire-order question in [Traefik #12100](https://github.com/traefik/traefik/issues/12100#issuecomment-6126567762). The reporter could not test a PROXY header sent **after** the outer TLS handshake.

It imports the actual pinned Traefik dialer and runs against a real Envoy mTLS listener, followed by a Go backend that expects PROXY then the original client TLS stream:

`Traefik outer mTLS → Envoy → PROXY header → origin TLS → ping/PONG`

Six serial cases compare PROXY v1/v2:

- Current Traefik default: PROXY before the outer TLS handshake. The experiment expects a prompt handshake failure from Envoy.
- Manual counterfactual: disable Traefik's pre-handshake header, finish the same verified outer TLS connection, then write the header inside it. Origin TLS, payload and header addresses must succeed.
- Ordinary TLS backend control: preserve the current PROXY-before-TLS order and verify success.

The after-handshake path is an explicit test control, **not a Traefik fix or configurable workaround**. There is no Consul control plane, reporter deployment, label configuration patch, production binary or upstream acceptance here. The reporter's existing configuration work remains theirs.

## Run

Requires Go1.27.3, Docker and Linux host networking. The manual GitHub workflow uses one standard public runner with a 12-minute bound; it does not run on a schedule. Image/action commits, the Traefik module and copied nested-module files are fixed in [provenance.json](provenance.json).

```sh
export ENVOY_IMAGE=envoyproxy/envoy@sha256:6a52be0cfec632bf31fe3197db078f0b3ea039a5a6d9edf2779abcbe34d81e20
docker pull --platform linux/amd64 "$ENVOY_IMAGE"
GOFLAGS=-mod=readonly GOMAXPROCS=2 GOMEMLIMIT=768MiB go test -tags=integration -count=1 -timeout=3m -v .
```

Dependency manifests preserve the pinned upstream graph to avoid resolving a different set of versions. The two small files under `dependencies/traefik-ext` are unmodified upstream source needed by Traefik's local module replacement. The experiment code is MIT; those files retain [Traefik's MIT license](LICENSE.traefik.txt).

Prepared with Codex assistance on behalf of kimjooyoon. [Traefik's policy](https://github.com/traefik/traefik/blob/eabc0714b367582dddbec155b5949889675b032d/AGENTS.md#ai-assistance-disclosure) permits assisted code but requires people to write issue/PR conversations themselves. This agent does not post upstream dialogue.
