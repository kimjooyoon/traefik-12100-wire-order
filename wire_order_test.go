//go:build integration

package wireorder_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"github.com/traefik/traefik/v3/pkg/tcp"
	traefiktls "github.com/traefik/traefik/v3/pkg/tls"
	"github.com/traefik/traefik/v3/pkg/types"
)

const (
	fixtureSource      = "198.51.100.23:53124"
	fixtureDestination = "203.0.113.7:443"
	caseTimeout        = 8 * time.Second
	ioTimeout          = 4 * time.Second
)

type caseResult struct {
	Name                      string `json:"name"`
	Version                   int    `json:"version"`
	Mode                      string `json:"mode"`
	Passed                    bool   `json:"passed"`
	ExpectedTLSHandshakeError bool   `json:"expected_tls_handshake_error"`
	ActualTraefikProxyEnabled bool   `json:"actual_traefik_proxy_enabled"`
	ManualPostTLSHeader       bool   `json:"manual_post_tls_header"`
	ObservedOutcome           string `json:"observed_outcome,omitempty"`
	Error                     string `json:"error,omitempty"`
	ProxyVersion              int    `json:"proxy_version,omitempty"`
	Source                    string `json:"source,omitempty"`
	Destination               string `json:"destination,omitempty"`
	Reply                     string `json:"reply,omitempty"`
}

type backendEvent struct {
	Stage       string `json:"stage"`
	Version     int    `json:"version,omitempty"`
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination,omitempty"`
	Error       string `json:"error,omitempty"`
}

// TestTLSProxyProtocolWireOrder observes transport ordering, without a Consul control plane or a product patch.
func TestTLSProxyProtocolWireOrder(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Fatal("this experiment requires Linux Docker host networking")
	}
	output := os.Getenv("OUTPUT_DIR")
	if output != "" {
		if err := os.MkdirAll(output, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var results []caseResult
	t.Cleanup(func() {
		passed := 0
		for _, r := range results {
			if r.Passed {
				passed++
			}
		}
		status := "FAIL"
		if !t.Failed() && len(results) == 6 && passed == 6 {
			status = "PASS"
		}
		writeEvidence(t, output, "results.json", map[string]any{
			"schema": "traefik-12100-wire-order/v1", "status": status,
			"scope":          "real Envoy mTLS outer tunnel; PROXY then inner/origin TLS; no Consul control plane or product fix",
			"observed_cases": len(results), "passed_cases": passed, "results": results,
		})
	})
	image := os.Getenv("ENVOY_IMAGE")
	if image == "" {
		t.Fatal("ENVOY_IMAGE must identify the pre-pulled Envoy fixture")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal(err)
	}
	certs := makeCertificates(t, t.TempDir())
	var dialWG sync.WaitGroup
	t.Cleanup(func() {
		done := make(chan struct{})
		go func() { dialWG.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(ioTimeout):
			t.Error("a Traefik dial did not return after fixture shutdown")
		}
	})
	origin := startBackend(t, certs.server, output, "envoy-origin")
	envoyAddress := startEnvoy(t, image, certs.dir, origin.address(), output)
	tests := []struct {
		mode    string
		version int
	}{
		{"envoy_default_pre_tls", 1}, {"envoy_default_pre_tls", 2},
		{"envoy_counterfactual_post_tls", 1}, {"envoy_counterfactual_post_tls", 2},
		{"ordinary_pre_tls", 1}, {"ordinary_pre_tls", 2},
	}
	for _, tc := range tests {
		name := fmt.Sprintf("%s_v%d", tc.mode, tc.version)
		t.Run(name, func(t *testing.T) {
			manual := tc.mode == "envoy_counterfactual_post_tls"
			negative := tc.mode == "envoy_default_pre_tls"
			result := caseResult{
				Name: name, Version: tc.version, Mode: tc.mode,
				ExpectedTLSHandshakeError: negative, ActualTraefikProxyEnabled: !manual,
				ManualPostTLSHeader: manual,
			}
			t.Cleanup(func() {
				result.Passed = !t.Failed()
				results = append(results, result)
				raw, _ := json.Marshal(result)
				t.Logf("WIRE_ORDER_RESULT %s", raw)
			})
			ctx, cancel := context.WithTimeout(t.Context(), caseTimeout)
			defer cancel()
			backend, address := origin, envoyAddress
			if tc.mode == "ordinary_pre_tls" {
				backend = startBackend(t, certs.server, output, name)
				address = backend.address()
			}
			transport := &dynamic.TCPServersTransport{TLS: &dynamic.TLSClientConfig{
				ServerName: "127.0.0.1", RootCAs: []types.FileOrContent{types.FileOrContent(certs.caPEM)},
				Certificates: traefiktls.Certificates{{
					CertFile: types.FileOrContent(certs.clientPEM), KeyFile: types.FileOrContent(certs.clientKeyPEM),
				}},
			}}
			if !manual {
				transport.ProxyProtocol = &dynamic.ProxyProtocol{Version: tc.version}
			}
			manager := tcp.NewDialerManager(nil)
			manager.Update(map[string]*dynamic.TCPServersTransport{"fixture": transport})
			dialer, err := manager.Build(&dynamic.TCPServersLoadBalancer{ServersTransport: "fixture"}, true)
			if err != nil {
				result.Error = err.Error()
				t.Error(err)
				return
			}
			conn, err := boundedDial(ctx, &dialWG, dialer, address)
			if negative {
				if conn != nil {
					_ = conn.Close()
				}
				if err != nil {
					result.Error = err.Error()
				}
				message := strings.ToLower(result.Error)
				if err == nil || ctx.Err() != nil || !strings.Contains(result.Error, "TLS handshake failed:") || strings.Contains(message, "timeout") || strings.Contains(message, "deadline") {
					t.Errorf("expected an actual TLS handshake error, got %v (context %v)", err, ctx.Err())
					return
				}
				result.ObservedOutcome = "tls_handshake_error"
				return
			}
			if err != nil {
				result.Error = err.Error()
				t.Error(err)
				return
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(ioTimeout)); err != nil {
				t.Error(err)
				return
			}
			if manual {
				client := fixtureClient{}
				header := proxyproto.HeaderProxyFromAddrs(byte(tc.version), client.RemoteAddr(), client.LocalAddr())
				if _, err := header.WriteTo(conn); err != nil {
					t.Error(err)
					return
				}
				inner := tls.Client(conn, &tls.Config{RootCAs: certs.pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12})
				if err := inner.HandshakeContext(ctx); err != nil {
					result.Error = err.Error()
					t.Error(err)
					return
				}
				conn = inner
			}
			if _, err := io.WriteString(conn, "ping"); err != nil {
				t.Error(err)
				return
			}
			reply := make([]byte, 4)
			if _, err := io.ReadFull(conn, reply); err != nil {
				t.Error(err)
				return
			}
			if string(reply) != "PONG" {
				t.Errorf("reply %q, want PONG", reply)
				return
			}
			select {
			case event := <-backend.successes:
				result.ProxyVersion, result.Source, result.Destination = event.Version, event.Source, event.Destination
				if event.Version != tc.version || event.Source != fixtureSource || event.Destination != fixtureDestination {
					t.Errorf("unexpected PROXY header: %+v", event)
					return
				}
			case <-ctx.Done():
				t.Error("origin did not report a validated header and completed exchange")
				return
			}
			result.Reply, result.ObservedOutcome = string(reply), "validated_proxy_header_inner_tls_and_pong"
		})
	}
}

type fixtureClient struct{}

func (fixtureClient) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 443}
}
func (fixtureClient) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("198.51.100.23"), Port: 53124}
}

func boundedDial(ctx context.Context, wg *sync.WaitGroup, dialer tcp.Dialer, address string) (net.Conn, error) {
	type outcome struct {
		conn net.Conn
		err  error
	}
	result := make(chan outcome)
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := dialer.DialContext(ctx, "tcp", address, fixtureClient{})
		select {
		case result <- outcome{conn, err}:
		case <-ctx.Done():
			if conn != nil {
				_ = conn.Close()
			}
		}
	}()
	select {
	case got := <-result:
		return got.conn, got.err
	case <-ctx.Done():
		return nil, fmt.Errorf("bounded dial: %w", ctx.Err())
	}
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

type wireBackend struct {
	listener  net.Listener
	server    tls.Certificate
	ctx       context.Context
	wg        sync.WaitGroup
	mu        sync.Mutex
	conns     map[net.Conn]struct{}
	events    []backendEvent
	successes chan backendEvent
}

func startBackend(t *testing.T, server tls.Certificate, output, name string) *wireBackend {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	b := &wireBackend{listener: listener, server: server, ctx: ctx, conns: make(map[net.Conn]struct{}), successes: make(chan backendEvent, 16)}
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			b.mu.Lock()
			b.conns[conn] = struct{}{}
			b.mu.Unlock()
			b.wg.Add(1)
			go b.serve(conn)
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		b.mu.Lock()
		for conn := range b.conns {
			_ = conn.Close()
		}
		b.mu.Unlock()
		b.wg.Wait()
		writeEvidence(t, output, name+"-events.json", b.events)
	})
	return b
}

func (b *wireBackend) address() string { return b.listener.Addr().String() }

func (b *wireBackend) serve(conn net.Conn) {
	defer b.wg.Done()
	defer conn.Close()
	defer func() { b.mu.Lock(); delete(b.conns, conn); b.mu.Unlock() }()
	event := backendEvent{Stage: "proxy_header"}
	defer func() { b.mu.Lock(); b.events = append(b.events, event); b.mu.Unlock() }()
	if err := conn.SetDeadline(time.Now().Add(ioTimeout)); err != nil {
		event.Error = err.Error()
		return
	}
	reader := bufio.NewReader(conn)
	header, err := proxyproto.Read(reader)
	if err != nil {
		event.Error = err.Error()
		return
	}
	if header.SourceAddr == nil || header.DestinationAddr == nil {
		event.Error = "PROXY header has no addresses"
		return
	}
	event.Version, event.Source, event.Destination = int(header.Version), header.SourceAddr.String(), header.DestinationAddr.String()
	if (event.Version != 1 && event.Version != 2) || event.Source != fixtureSource || event.Destination != fixtureDestination {
		event.Error = "PROXY header does not match the fixture"
		return
	}
	event.Stage = "inner_tls"
	inner := tls.Server(bufferedConn{Conn: conn, reader: reader}, &tls.Config{Certificates: []tls.Certificate{b.server}, MinVersion: tls.VersionTLS12})
	if err := inner.HandshakeContext(b.ctx); err != nil {
		event.Error = err.Error()
		return
	}
	event.Stage = "ping"
	message := make([]byte, 4)
	if _, err := io.ReadFull(inner, message); err != nil {
		event.Error = err.Error()
		return
	}
	if !bytes.Equal(message, []byte("ping")) {
		event.Error = fmt.Sprintf("unexpected message %q", message)
		return
	}
	if _, err := io.WriteString(inner, "PONG"); err != nil {
		event.Error = err.Error()
		return
	}
	event.Stage = "completed"
	select {
	case b.successes <- event:
	case <-b.ctx.Done():
	}
}

type certificates struct {
	dir          string
	caPEM        []byte
	clientPEM    []byte
	clientKeyPEM []byte
	server       tls.Certificate
	pool         *x509.CertPool
}

func makeCertificates(t *testing.T, dir string) certificates {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "wire-order test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	issue := func(serial int64, usage x509.ExtKeyUsage) ([]byte, []byte) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cert := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "wire-order fixture"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		if usage == x509.ExtKeyUsageServerAuth {
			cert.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		der, err := x509.CreateCertificate(rand.Reader, cert, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	}
	serverPEM, serverKey := issue(2, x509.ExtKeyUsageServerAuth)
	clientPEM, clientKey := issue(3, x509.ExtKeyUsageClientAuth)
	for name, data := range map[string][]byte{"ca.pem": caPEM, "server.pem": serverPEM, "server-key.pem": serverKey, "client.pem": clientPEM, "client-key.pem": clientKey} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	server, err := tls.X509KeyPair(serverPEM, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("invalid generated CA")
	}
	return certificates{dir: dir, caPEM: caPEM, clientPEM: clientPEM, clientKeyPEM: clientKey, server: server, pool: pool}
}

func startEnvoy(t *testing.T, image, dir, backend, output string) string {
	t.Helper()
	port, adminPort := freePorts(t)
	_, backendPort, err := net.SplitHostPort(backend)
	if err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf(`admin:
  address:
    socket_address: { address: 127.0.0.1, port_value: %d }
static_resources:
  listeners:
  - name: outer_mtls
    address:
      socket_address: { address: 127.0.0.1, port_value: %d }
    filter_chains:
    - transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          require_client_certificate: true
          common_tls_context:
            tls_certificates:
            - certificate_chain: { filename: /work/server.pem }
              private_key: { filename: /work/server-key.pem }
            validation_context:
              trusted_ca: { filename: /work/ca.pem }
      filters:
      - name: envoy.filters.network.tcp_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
          stat_prefix: wire_order
          cluster: origin
          idle_timeout: 5s
  clusters:
  - name: origin
    connect_timeout: 2s
    type: STATIC
    load_assignment:
      cluster_name: origin
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address: { address: 127.0.0.1, port_value: %s }
`, adminPort, port, backendPort)
	if err := os.WriteFile(filepath.Join(dir, "envoy.yaml"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	writeRawEvidence(t, output, "envoy-config.yaml", []byte(config))
	inspect, err := dockerCommand(10*time.Second, "image", "inspect", image)
	writeRawEvidence(t, output, "image-inspect.json", inspect)
	if err != nil {
		t.Fatalf("Envoy image must already be present: %v", err)
	}
	name := fmt.Sprintf("traefik-12100-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		logs, err := dockerCommand(5*time.Second, "logs", "--timestamps", name)
		writeRawEvidence(t, output, "envoy.log", logs)
		if err != nil {
			t.Logf("capture Envoy logs: %v", err)
		}
		if raw, err := dockerCommand(5*time.Second, "rm", "--force", name); err != nil {
			t.Errorf("remove Envoy container: %v (%s)", err, raw)
		}
	})
	args := []string{"run", "--detach", "--pull=never", "--name", name, "--network", "host", "--cpus", "1", "--memory", "256m", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "--mount", "type=bind,src=" + dir + ",dst=/work,readonly", image, "-c", "/work/envoy.yaml", "--concurrency", "1", "--disable-hot-restart", "--log-level", "debug"}
	if raw, err := dockerCommand(20*time.Second, args...); err != nil {
		t.Fatalf("start Envoy: %v (%s)", err, raw)
	}
	version, err := dockerCommand(5*time.Second, "exec", name, "envoy", "--version")
	writeRawEvidence(t, output, "envoy-version.txt", version)
	if err != nil {
		t.Fatalf("read Envoy version: %v", err)
	}
	client := &http.Client{Timeout: 300 * time.Millisecond}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/ready", adminPort), nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return fmt.Sprintf("127.0.0.1:%d", port)
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal("Envoy did not become ready before the deadline")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func freePorts(t *testing.T) (int, int) {
	t.Helper()
	first, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	return first.Addr().(*net.TCPAddr).Port, second.Addr().(*net.TCPAddr).Port
}

func dockerCommand(timeout time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return exec.CommandContext(ctx, "docker", args...).CombinedOutput()
}

func writeEvidence(t *testing.T, output, name string, value any) {
	t.Helper()
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Error(err)
		return
	}
	writeRawEvidence(t, output, name, append(raw, '\n'))
}

func writeRawEvidence(t *testing.T, output, name string, raw []byte) {
	t.Helper()
	if output != "" {
		if err := os.WriteFile(filepath.Join(output, name), raw, 0o644); err != nil {
			t.Error(err)
		}
	}
}
