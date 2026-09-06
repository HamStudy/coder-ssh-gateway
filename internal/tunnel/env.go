package tunnel

import (
	"os"

	"github.com/HamStudy/coder-ssh-gateway/internal/core"
)

func BuildEnv(dep core.Deployment, token []byte) []string {
	env := []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"HOME=" + dep.WorkingDir,
		"TMPDIR=" + os.TempDir(),
		"CODER_URL=" + dep.CoderURL.String(),
		"CODER_SESSION_TOKEN=" + string(token),
		"CODER_NO_VERSION_WARNING=true",
		"CODER_NO_FEATURE_WARNING=true",
		"CODER_DISABLE_NETWORK_TELEMETRY=" + boolString(dep.Network.DisableNetworkTelemetry),
	}
	if dep.TLS.CAFile != "" {
		env = append(env, "CODER_CLIENT_TLS_CA_FILE="+dep.TLS.CAFile)
	}
	if dep.TLS.CertFile != "" {
		env = append(env, "CODER_CLIENT_TLS_CERT_FILE="+dep.TLS.CertFile)
	}
	if dep.TLS.KeyFile != "" {
		env = append(env, "CODER_CLIENT_TLS_KEY_FILE="+dep.TLS.KeyFile)
	}
	if dep.Network.Proxy != "" {
		env = append(env, "HTTPS_PROXY="+dep.Network.Proxy)
	}
	if dep.Network.NoProxy != "" {
		env = append(env, "NO_PROXY="+dep.Network.NoProxy)
	}
	return env
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
