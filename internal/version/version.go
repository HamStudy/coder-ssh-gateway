package version

import "fmt"

var Version = "dev"
var Commit = "dev"
var Date = "dev"

func String() string {
	return fmt.Sprintf("coder-ssh-gateway/%s (%s, %s)", Version, Commit, Date)
}
