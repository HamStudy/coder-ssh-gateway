package secretbox

import (
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// CredentialAAD builds the authenticated associated data for credential
// records, byte-stable per design section 22.1: the six lines
// "coder-ssh-gateway", "schema=v1", "deployment=<uuid>", "account=<uuid>",
// "record=credential", "generation=<int>" joined with "\n".
func CredentialAAD(deploymentID, accountID uuid.UUID, generation int64) []byte {
	return []byte(strings.Join([]string{
		"coder-ssh-gateway",
		"schema=v1",
		"deployment=" + deploymentID.String(),
		"account=" + accountID.String(),
		"record=credential",
		"generation=" + strconv.FormatInt(generation, 10),
	}, "\n"))
}
