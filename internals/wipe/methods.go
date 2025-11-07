package wipe

import (
	"fmt"
	"os/exec"
	"syscall"
)

func eraseNvme(device string) error {
	args := []string{"format", "--ses=1", device}
	cmd := exec.Command("nvme-cli", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nvme-cli failed: %v, output: %s", err, output)
	}
	return nil
}

func eraseSata(device string) error {
	args := []string{"--user-master", "u", "--security-erase-enhanced", "p", device}
	cmd := exec.Command("hdparm", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("hdparm failed: %v, output: %s", err, output)
	}
	return nil
}

