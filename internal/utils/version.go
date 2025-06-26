// Package utils provides versioning information for the Scroll paymaster service.
package utils

import (
	"fmt"
	"runtime/debug"
)

var tag = "v0.0.4"

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
