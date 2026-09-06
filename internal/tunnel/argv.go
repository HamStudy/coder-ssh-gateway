package tunnel

import (
	"regexp"

	"github.com/taxilian/coder-ssh-gateway/internal/core"
)

var targetGrammar = regexp.MustCompile(`^[a-z0-9.-]+$`)

func BuildArgv(dep core.Deployment, route core.Route) []string {
	if !targetGrammar.MatchString(route.WorkspaceHost) {
		return nil
	}
	argv := []string{
		"--global-config", dep.GlobalConfig,
		"ssh",
		"--stdio",
		"--wait=" + dep.WaitMode,
	}
	if !dep.Autostart {
		argv = append(argv, "--disable-autostart=true")
	}
	argv = append(argv, route.WorkspaceHost)
	return argv
}
