package app

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/HamStudy/coder-ssh-gateway/internal/config"
	"github.com/HamStudy/coder-ssh-gateway/internal/core"
	"github.com/HamStudy/coder-ssh-gateway/internal/store"
)

func (c *cli) cmdAdmin(args []string) int {
	if len(args) == 0 {
		adminUsage(c.stderr)
		return exitUsage
	}
	switch args[0] {
	case "account":
		return c.cmdAdminAccount(args[1:])
	case "key":
		return c.cmdAdminKey(args[1:])
	case "credential":
		return c.cmdAdminCredential(args[1:])
	case "disconnect":
		return c.cmdDisconnect(args[1:])
	default:
		fmt.Fprintf(c.stderr, "error: unknown admin command %q\n", args[0])
		adminUsage(c.stderr)
		return exitUsage
	}
}

func adminUsage(w io.Writer) {
	fmt.Fprint(w, `usage:
  admin account add --label NAME (--coder-user-id UUID | --bind-on-first-token) [--deployment LABEL]
  admin account list
  admin account disable --account UUID
  admin account enable --account UUID
  admin key add --account UUID --file ./key.pub --label NAME
  admin key list --account UUID
  admin key disable --key UUID
  admin key enable --key UUID
  admin credential status --account UUID
  admin credential set --account UUID [--stdin]
  admin credential clear --account UUID
  admin disconnect --account UUID
`)
}

func (c *cli) adminUsageErr(scope string) int {
	fmt.Fprintf(c.stderr, "error: unknown or missing admin %s subcommand\n", scope)
	adminUsage(c.stderr)
	return exitUsage
}

func (c *cli) cmdAdminAccount(args []string) int {
	if len(args) == 0 {
		return c.adminUsageErr("account")
	}
	switch args[0] {
	case "add":
		return c.accountAdd(args[1:])
	case "list":
		return c.accountList(args[1:])
	case "disable":
		return c.accountSetEnabled(args[1:], false)
	case "enable":
		return c.accountSetEnabled(args[1:], true)
	default:
		return c.adminUsageErr("account")
	}
}

func (c *cli) cmdAdminKey(args []string) int {
	if len(args) == 0 {
		return c.adminUsageErr("key")
	}
	switch args[0] {
	case "add":
		return c.keyAdd(args[1:])
	case "list":
		return c.keyList(args[1:])
	case "disable":
		return c.keySetEnabled(args[1:], false)
	case "enable":
		return c.keySetEnabled(args[1:], true)
	default:
		return c.adminUsageErr("key")
	}
}

// accountAdd implements §10.5 enrollment: admin-bound (known Coder UUID) or
// explicit bind-on-first-token. Exactly one binding mode is required.
func (c *cli) accountAdd(args []string) int {
	fs := c.newFlagSet("account add")
	label := fs.String("label", "", "human label for the account")
	coderUserID := fs.String("coder-user-id", "", "bind to this Coder user UUID")
	bindOnFirst := fs.Bool("bind-on-first-token", false, "bind the Coder user UUID returned by the first valid token")
	deployment := fs.String("deployment", "", "deployment label (default: the configured deployment)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *label == "" {
		fmt.Fprintf(c.stderr, "error: --label is required\n")
		return exitUsage
	}
	if (*coderUserID == "") == !*bindOnFirst {
		fmt.Fprintf(c.stderr, "error: exactly one of --coder-user-id or --bind-on-first-token is required\n")
		return exitUsage
	}
	cfg, st, code := c.loadConfigAndStore()
	if code != exitOK {
		return code
	}
	defer st.Close()

	if *deployment != "" && *deployment != cfg.Deployment.ID {
		fmt.Fprintf(c.stderr, "error: unknown deployment %q (configured: %q)\n", *deployment, cfg.Deployment.ID)
		return exitError
	}
	acct := core.Account{
		ID:               uuid.New(),
		DeploymentID:     DeploymentUUID(cfg.Deployment.ID),
		Label:            *label,
		BindOnFirstToken: *bindOnFirst,
		Enabled:          true,
	}
	if *coderUserID != "" {
		uid, err := uuid.Parse(*coderUserID)
		if err != nil {
			fmt.Fprintf(c.stderr, "error: --coder-user-id: %v\n", err)
			return exitUsage
		}
		acct.CoderUserID = &uid
	}
	if err := st.AddAccount(acct); err != nil {
		fmt.Fprintf(c.stderr, "error: adding account: %v\n", err)
		return exitError
	}
	fmt.Fprintf(c.stdout, "account %s created (label=%q deployment=%q", acct.ID, acct.Label, cfg.Deployment.ID)
	if acct.CoderUserID != nil {
		fmt.Fprintf(c.stdout, " coder_user_id=%s", *acct.CoderUserID)
	} else {
		fmt.Fprintf(c.stdout, " bind_on_first_token=true")
	}
	fmt.Fprintln(c.stdout, ")")
	return exitOK
}

func (c *cli) accountList(args []string) int {
	fs := c.newFlagSet("account list")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	_, st, code := c.loadConfigAndStore()
	if code != exitOK {
		return code
	}
	defer st.Close()
	accounts, err := st.ListAccounts()
	if err != nil {
		fmt.Fprintf(c.stderr, "error: listing accounts: %v\n", err)
		return exitError
	}
	if len(accounts) == 0 {
		fmt.Fprintln(c.stdout, "no accounts")
		return exitOK
	}
	for _, a := range accounts {
		bound := "unbound"
		if a.CoderUserID != nil {
			bound = a.CoderUserID.String()
		}
		fmt.Fprintf(c.stdout, "id=%s label=%q enabled=%t coder_user_id=%s username=%q bind_on_first_token=%t\n",
			a.ID, a.Label, a.Enabled, bound, a.CachedUsername, a.BindOnFirstToken)
	}
	return exitOK
}

func (c *cli) accountSetEnabled(args []string, enabled bool) int {
	fs := c.newFlagSet("account enable/disable")
	accountID := fs.String("account", "", "account UUID")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	id, err := parseUUIDFlag("--account", *accountID)
	if err != nil {
		fmt.Fprintf(c.stderr, "error: %v\n", err)
		return exitUsage
	}
	_, st, code := c.loadConfigAndStore()
	if code != exitOK {
		return code
	}
	defer st.Close()
	if err := st.SetAccountEnabled(id, enabled); err != nil {
		fmt.Fprintf(c.stderr, "error: %v\n", err)
		return exitError
	}
	verb := "disabled"
	if enabled {
		verb = "enabled"
	}
	fmt.Fprintf(c.stdout, "account %s %s\n", id, verb)
	return exitOK
}

// keyAdd registers a public key and prints its SHA256 fingerprint (§29).
func (c *cli) keyAdd(args []string) int {
	fs := c.newFlagSet("key add")
	accountID := fs.String("account", "", "account UUID")
	file := fs.String("file", "", "authorized_keys-formatted public key file")
	label := fs.String("label", "", "human label for the key")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	id, err := parseUUIDFlag("--account", *accountID)
	if err != nil {
		fmt.Fprintf(c.stderr, "error: %v\n", err)
		return exitUsage
	}
	if *file == "" {
		fmt.Fprintf(c.stderr, "error: --file is required\n")
		return exitUsage
	}
	raw, err := os.ReadFile(*file)
	if err != nil {
		fmt.Fprintf(c.stderr, "error: reading key file: %v\n", err)
		return exitError
	}
	pub, comment, _, rest, err := ssh.ParseAuthorizedKey(raw)
	if err != nil {
		fmt.Fprintf(c.stderr, "error: parsing public key: %v\n", err)
		return exitError
	}
	if strings.TrimSpace(string(rest)) != "" {
		fmt.Fprintf(c.stderr, "error: key file must contain exactly one public key\n")
		return exitError
	}
	if *label == "" {
		*label = comment
	}

	_, st, code := c.loadConfigAndStore()
	if code != exitOK {
		return code
	}
	defer st.Close()
	rec, err := st.AddKey(id, pub, *label)
	if err != nil {
		fmt.Fprintf(c.stderr, "error: adding key: %v\n", err)
		return exitError
	}
	fmt.Fprintf(c.stdout, "key %s added for account %s\n", rec.ID, id)
	fmt.Fprintf(c.stdout, "fingerprint: %s\n", rec.Fingerprint)
	fmt.Fprintf(c.stdout, "algorithm: %s label: %q\n", rec.Algorithm, *label)
	return exitOK
}

func (c *cli) keyList(args []string) int {
	fs := c.newFlagSet("key list")
	accountID := fs.String("account", "", "account UUID")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	id, err := parseUUIDFlag("--account", *accountID)
	if err != nil {
		fmt.Fprintf(c.stderr, "error: %v\n", err)
		return exitUsage
	}
	_, st, code := c.loadConfigAndStore()
	if code != exitOK {
		return code
	}
	defer st.Close()
	keys, err := st.ListKeysForAccount(id)
	if err != nil {
		fmt.Fprintf(c.stderr, "error: listing keys: %v\n", err)
		return exitError
	}
	if len(keys) == 0 {
		fmt.Fprintln(c.stdout, "no keys")
		return exitOK
	}
	for _, k := range keys {
		fmt.Fprintf(c.stdout, "id=%s fingerprint=%s algorithm=%s enabled=%t\n", k.ID, k.Fingerprint, k.Algorithm, k.Enabled)
	}
	return exitOK
}

func (c *cli) keySetEnabled(args []string, enabled bool) int {
	fs := c.newFlagSet("key enable/disable")
	keyID := fs.String("key", "", "key UUID")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	id, err := parseUUIDFlag("--key", *keyID)
	if err != nil {
		fmt.Fprintf(c.stderr, "error: %v\n", err)
		return exitUsage
	}
	_, st, code := c.loadConfigAndStore()
	if code != exitOK {
		return code
	}
	defer st.Close()
	if err := st.SetKeyEnabled(id, enabled); err != nil {
		fmt.Fprintf(c.stderr, "error: %v\n", err)
		return exitError
	}
	verb := "disabled"
	if enabled {
		verb = "enabled"
	}
	fmt.Fprintf(c.stdout, "key %s %s\n", id, verb)
	return exitOK
}

// cmdDisconnect is the §23.4 explicit account disconnect. In the MVP it
// disables the account (blocking new authentication immediately, since the
// enabled flag is read on every key lookup) and reports honestly that
// active tunnels are not terminated.
func (c *cli) cmdDisconnect(args []string) int {
	fs := c.newFlagSet("disconnect")
	accountID := fs.String("account", "", "account UUID")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	id, err := parseUUIDFlag("--account", *accountID)
	if err != nil {
		fmt.Fprintf(c.stderr, "error: %v\n", err)
		return exitUsage
	}
	_, st, code := c.loadConfigAndStore()
	if code != exitOK {
		return code
	}
	defer st.Close()
	if _, err := st.GetAccount(id); err != nil {
		fmt.Fprintf(c.stderr, "error: %v\n", err)
		return exitError
	}
	if err := st.SetAccountEnabled(id, false); err != nil {
		fmt.Fprintf(c.stderr, "error: %v\n", err)
		return exitError
	}
	fmt.Fprintf(c.stdout, `account %s disconnected (disabled): new SSH authentication is blocked immediately.
Active tunnels are NOT terminated (section 23.4): in this MVP, disabling an
account or revoking a credential never kills established connections; they
end when clients disconnect or the coder process exits. Registry-based
forced termination of active tunnels is deferred to a future release.
Re-enable with: coder-ssh-gateway admin account enable --account %s
`, id, id)
	return exitOK
}

func parseUUIDFlag(name, val string) (uuid.UUID, error) {
	if val == "" {
		return uuid.Nil, fmt.Errorf("%s is required", name)
	}
	id, err := uuid.Parse(val)
	if err != nil {
		return uuid.Nil, fmt.Errorf("%s: %v", name, err)
	}
	return id, nil
}

// loadConfigAndStore is the shared preamble for admin commands: parse config
// (no validation), open the store, seed the deployment record.
func (c *cli) loadConfigAndStore() (*config.Config, *store.Store, int) {
	cfg, err := c.loadConfig()
	if err != nil {
		fmt.Fprintf(c.stderr, "error: %v\n", err)
		return nil, nil, exitError
	}
	st, err := c.openStore(cfg, nil)
	if err != nil {
		fmt.Fprintf(c.stderr, "error: opening state store: %v\n", err)
		return nil, nil, exitError
	}
	return cfg, st, exitOK
}
