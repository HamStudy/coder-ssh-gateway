// Command coder-ssh-gateway is the operator/admin CLI for the gateway (§29).
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/HamStudy/coder-ssh-gateway/internal/app"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(app.Run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
