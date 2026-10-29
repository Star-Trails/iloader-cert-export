//go:build !windows

package exporter

import "os/exec"

func configureCommand(cmd *exec.Cmd) {}
