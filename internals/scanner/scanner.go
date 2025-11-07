package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
)

type LsblkOutput struct {
	BlockDevices []BlockDevice `json:"blockdevices"`
}

type BlockDevice struct {
	Name   string `json:"name"`   // e.g., "sda" or "nvme0n1"
	Model  string `json:"model"`  // Device model
	Serial string `json:"serial"` // Device serial number
	Type   string `json:"type"`   // e.g., "disk", "part"
	Size   string `json:"size"`   // Human-readable size
	IsROTA bool   `json:"rota"`   // "rotational" - true for HDD, false for SSD/NVMe
}

func DiscoverDevices() ([]BlockDevice, error) {
	// -J ensures the output is JSON
	// -o specifies the columns we want
	cmd := exec.Command("lsblk", "-J", "-o", "NAME,MODEL,SERIAL,TYPE,SIZE,ROTA")
	
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		log.Printf("lsblk command stderr: %s", stderr.String())
		return nil, fmt.Errorf("lsblk command failed: %v", err)
	}

	var lsblkData LsblkOutput
	if err := json.Unmarshal(out.Bytes(), &lsblkData); err != nil {
		return nil, fmt.Errorf("failed to parse lsblk JSON: %v. Raw JSON: %s", err, out.String())
	}

	// Filter out partitions, we only want the main "disk" devices
	var disks []BlockDevice
	for _, dev := range lsblkData.BlockDevices {
		if dev.Type == "disk" {
			disks = append(disks, dev)
		}
	}
	
	if len(disks) == 0 {
		log.Println("Warning: lsblk found 0 devices of type 'disk'.")
	}
	
	return disks, nil
}
