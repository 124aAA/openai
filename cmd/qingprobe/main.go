package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"qingnode/internal/probecli"
	"syscall"
)

var version = "0.3.0"
var revision = "source"

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Printf("QingProbe %s (%s)\n", version, revision)
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := probecli.Execute(ctx, os.Args[1:], probecli.Hooks{Version: version + "/" + revision}); err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, "[ERROR]", err)
		os.Exit(1)
	}
}
