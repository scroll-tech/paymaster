// Package utils provides logging functionality for the Scroll paymaster service.
package utils

import (
	"os"

	"github.com/ethereum/go-ethereum/log"
	"github.com/urfave/cli/v2"
)

// LogSetup configures the logging system based on CLI context flags
func LogSetup(ctx *cli.Context) {
	handler := log.StreamHandler(os.Stderr, log.TerminalFormat(true))
	verbosity := ctx.Int(verbosityFlag.Name)
	handler = log.LvlFilterHandler(log.Lvl(verbosity), handler)
	log.Root().SetHandler(handler)
}
