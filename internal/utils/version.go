package utils

import (
	"fmt"
	"runtime/debug"
)

var tag = "v0.0.1"

var commit = func() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				value := setting.Value
				if len(value) >= 7 {
					return value[:7]
				}
				return value
			}
		}
	}
	// Set default value for integration test.
	return "000000"
}()

// Version denotes the version of paymaster.
var Version = fmt.Sprintf("%s-%s", tag, commit)
