package main

import (
    "encoding/json"
    "fmt"
    "os"
	"runtime"
    "time"

    "cloudnine-sih2025/internals/cert"
    "cloudnine-sih2025/internals/wipe"
    "cloudnine-sih2025/pkg/log"
    "github.com/jung-kurt/gofpdf"
)

var (
    device  string
    passes  int
    output  string
    certDir string
)

func main() {
    log.Init()
    log.Info("Starting secure wipe process for device: %s", device)
    log.Info("Platform: %s, Passes: %d", runtime.GOOS, passes)

    startTime := time.Now()
    err := wipe.Wipe(device)
    if err != nil {
        log.Error("Wipe failed: %v", err)
        os.Exit(1)
    }
    duration := time.Since(startTime)
    log.Info("Wipe completed successfully in %v", duration)

    cert := cert.GenerateCertificate(device, passes, duration, runtime.GOOS)
    if err := saveCertificate(cert, output); err != nil {
        log.Error("Failed to save certificate: %v", err)
        os.Exit(1)
    }

    log.Info("Certificate saved to: %s.pdf and %s.json", output, output)
    log.Info("Wipe process finished.")
}

func saveCertificate(cert *cert.Certificate, output string) error {
    jsonData, err := json.MarshalIndent(cert, "", "  ")
    if err != nil {
        return err
    }
    if err := os.WriteFile(output+".json", jsonData, 0644); err != nil {
        return err
    }

    pdf := gofpdf.New("P", "mm", "A4", "")
    pdf.AddPage()
    pdf.SetFont("Arial", "B", 16)
    pdf.Cell(40, 10, "Secure Wipe Certificate")
    pdf.Ln(10)
    pdf.SetFont("Arial", "", 12)
    pdf.Cell(40, 10, fmt.Sprintf("Device: %s", cert.Device))
    pdf.Ln(10)
    pdf.Cell(40, 10, fmt.Sprintf("Passes: %d", cert.Passes))
    pdf.Ln(10)
    pdf.Cell(40, 10, fmt.Sprintf("Duration: %s", cert.Duration))
    pdf.Ln(10)
    pdf.Cell(40, 10, fmt.Sprintf("Platform: %s", cert.Platform))
    return pdf.OutputFileAndClose(output + ".pdf")
}
