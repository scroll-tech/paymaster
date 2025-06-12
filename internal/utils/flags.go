// Package utils provides common flags for the Scroll paymaster service.
package utils

import (
	"github.com/urfave/cli/v2"
)

var (
	// CommonFlags is used for app common flags in different modules
	CommonFlags = []cli.Flag{
		&ConfigFileFlag,

		&HTTPEnabledFlag,
		&HTTPListenAddrFlag,
		&HTTPPortFlag,

		&verbosityFlag,
		&logDebugFlag,

		&MetricsEnabled,
		&MetricsAddr,
		&MetricsPort,

		&DBFlag,
		&DBMigrateFlag,
		&DBRollBackFlag,
		&DBResetFlag,
	}
	// ConfigFileFlag load json type config file.
	ConfigFileFlag = cli.StringFlag{
		Name:  "config",
		Usage: "JSON configuration file.",
		Value: "./conf/config.json",
	}

	// HTTPEnabledFlag enable rpc server.
	HTTPEnabledFlag = cli.BoolFlag{
		Name:  "http",
		Usage: "Enable the HTTP-RPC server.",
		Value: false,
	}
	// HTTPListenAddrFlag set the http address.
	HTTPListenAddrFlag = cli.StringFlag{
		Name:  "http.addr",
		Usage: "HTTP-RPC server listening interface.",
		Value: "localhost",
	}
	// HTTPPortFlag set http.port.
	HTTPPortFlag = cli.IntFlag{
		Name:  "http.port",
		Usage: "HTTP-RPC server listening port.",
		Value: 8750,
	}

	// verbosityFlag log level.
	verbosityFlag = cli.IntFlag{
		Name:  "verbosity",
		Usage: "Logging verbosity: 0=silent, 1=error, 2=warn, 3=info, 4=debug, 5=detail.",
		Value: 3,
	}

	// logDebugFlag make log messages with call-site location
	logDebugFlag = cli.BoolFlag{
		Name:  "log.debug",
		Usage: "Prepends log messages with call-site location (file and line number).",
	}

	// MetricsEnabled enable metrics collection and reporting
	MetricsEnabled = cli.BoolFlag{
		Name:     "metrics",
		Usage:    "Enable metrics collection and reporting.",
		Category: "METRICS",
		Value:    false,
	}
	// MetricsAddr is listening address of Metrics reporting server
	MetricsAddr = cli.StringFlag{
		Name:     "metrics.addr",
		Usage:    "Metrics reporting server listening address.",
		Category: "METRICS",
		Value:    "127.0.0.1",
	}
	// MetricsPort is listening port of Metrics reporting server
	MetricsPort = cli.IntFlag{
		Name:     "metrics.port",
		Usage:    "Metrics reporting server listening port.",
		Category: "METRICS",
		Value:    6060,
	}

	// DBFlag enable db operation.
	DBFlag = cli.BoolFlag{
		Name:  "db",
		Usage: "Enable db operation.",
		Value: false,
	}
	// DBMigrateFlag migrate db.
	DBMigrateFlag = cli.BoolFlag{
		Name:  "db.migrate",
		Usage: "Migrate the database to the latest version.",
		Value: false,
	}
	// DBRollBackFlag rollback db.
	DBRollBackFlag = cli.Int64Flag{
		Name:  "db.rollback",
		Usage: "Roll back the database to a previous <version>.",
		Value: 1000000, // Default value set to a very large number indicating no rollback.
	}
	// DBResetFlag reset db.
	DBResetFlag = cli.BoolFlag{
		Name:  "db.reset",
		Usage: "Clean and reset database.",
		Value: false,
	}
)
