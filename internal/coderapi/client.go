package coderapi

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/HamStudy/coder-ssh-gateway/internal/version"
)

const (
	DefaultTimeout = 10 * time.Second
	MaxBodyBytes   = 1 << 20 // 1 MiB response cap (§11.2)
)

// Options configures the hardened Coder API HTTP client. Zero value is
// usable: system roots, 10s timeout, no client certificate, no extra headers.
type Options struct {
	Timeout   time.Duration
	RootCAs   *x509.CertPool
	UserAgent string
	// Headers are administrator-configured static headers (§11.2) added to
	// every request.
	Headers http.Header
	// ClientCertificate and ClientKey are PEM-encoded mTLS credentials. Both
	// must be set together; leaving both empty disables mTLS.
	ClientCertificate []byte
	ClientKey         []byte
}

func (o *Options) timeout() time.Duration {
	if o.Timeout <= 0 {
		return DefaultTimeout
	}
	return o.Timeout
}

func (o *Options) userAgent() string {
	if o.UserAgent != "" {
		return o.UserAgent
	}
	return "coder-ssh-gateway/" + version.Version
}

// NewHTTPClient builds an *http.Client hardened per §11.2: verified TLS with
// system roots plus any pool in opts.RootCAs, optional mTLS, bounded timeout,
// fail-closed redirects, and a shared bounded transport.
func NewHTTPClient(opts Options) (*http.Client, error) {
	pool := opts.RootCAs
	if pool == nil {
		p, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("load system cert pool: %w", err)
		}
		pool = p
	}

	tlsCfg := &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}

	haveCert := len(opts.ClientCertificate) > 0
	haveKey := len(opts.ClientKey) > 0
	if haveCert != haveKey {
		return nil, errors.New("coderapi: client certificate and key must be configured together")
	}
	if haveCert {
		pair, err := tls.X509KeyPair(opts.ClientCertificate, opts.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{pair}
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   opts.timeout(),
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:       tlsCfg,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          8,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   opts.timeout(),
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   opts.timeout(),
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return redirectError()
		},
	}, nil
}
