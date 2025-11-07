package wipe

import (
    "fmt"
	"syscall"

    "cloudnine-sih2025/pkg/log"
)


func Wipe(device string) error {
	log.Info("Wiping device %s", device)
	err := eraseNvme(device)
	if err != nil {
		return err
	}
	err = eraseSata(device)
	if err != nil {
		return err
	}
	fmt.Println("Wipe complete")
	syscall.Sync()
	return nil
}

