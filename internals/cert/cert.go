package cert

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "os"
    "strings"
    "time"
	"github.com/jung-kurt/gofpdf"
    "cloudnine-sih2025/pkg/log"
)

type Certificate struct {
    Device     string    `json:"device"`
    Passes     int       `json:"passes"`
    StartTime  time.Time `json:"start_time"`
    EndTime    time.Time `json:"end_time"`
    Duration   string    `json:"duration"`
    Platform   string    `json:"platform"`
    Method     string    `json:"method"`
    Signature  string    `json:"signature"`
    PublicKey  string    `json:"public_key"`
    Standards  []string  `json:"standards"`
}

func GenerateCertificate(device string, duration time.Duration, platform string) *Certificate {
    cert := &Certificate{
        Device:    device,
        StartTime: time.Now().Add(-duration),
        EndTime:   time.Now(),
        Duration:  duration.String(),
        Platform:  platform,
        Method:    "(NIST 800-88 compliant)",
        Standards: []string{"NIST SP 800-88"},
    }

    privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        log.Warn("Failed to generate keys for demo: %v", err)
        return cert
    }

    data, _ := json.Marshal(cert)
    hash := sha256.Sum256(data)
    sig, err := ecdsa.SignASN1(rand.Reader, privKey, hash[:])
    if err != nil {
        log.Warn("Signing failed: %v", err)
    } else {
        cert.Signature = hex.EncodeToString(sig)
        pubKeyBytes := elliptic.Marshal(elliptic.P256(), privKey.PublicKey.X, privKey.PublicKey.Y)
        cert.PublicKey = hex.EncodeToString(pubKeyBytes)
    }

    return cert
}

func LoadCertificate(path string) (*Certificate, error) {
    data, err := ioutil.ReadFile(path)
    if err != nil {
        return nil, err
    }

    cert := &Certificate{}
    err = json.Unmarshal(data, cert)
    if err != nil {
        return nil, err
    }

    return cert, nil
}

// saveCertificate saves the certificate to a PDF and JSON file.
func SaveCertificate(cert *Certificate, output string) error {
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
	pdf.Cell(40, 10, fmt.Sprintf("Duration: %s", cert.Duration))
	pdf.Ln(10)
	pdf.Cell(40, 10, fmt.Sprintf("Platform: %s", cert.Platform))
	return pdf.OutputFileAndClose(output + ".pdf")
}

func (c *Certificate) GetDevice() string {
    return c.Device
}

func (c *Certificate) GetStartTime() time.Time {
    return c.StartTime
}

func (c *Certificate) GetEndTime() time.Time {
    return c.EndTime
}

func (c *Certificate) GetDuration() string {
    return c.Duration
}

func (c *Certificate) GetPlatform() string {
    return c.Platform
}

func (c *Certificate) GetMethod() string {
    return c.Method
}

func (c *Certificate) GetSignature() string {
    return c.Signature
}

func (c *Certificate) GetPublicKey() string {
    return c.PublicKey
}

func (c *Certificate) GetStandards() []string {
    return c.Standards
}

func (c *Certificate) String() string {
    return fmt.Sprintf("Device: %s\nStart Time: %s\nEnd Time: %s\nDuration: %s\nPlatform: %s\nMethod: %s\nSignature: %s\nPublic Key: %s\nStandards: %s\n",
        c.Device, c.StartTime.Format(time.RFC3339), c.EndTime.Format(time.RFC3339), c.Duration, c.Platform, c.Method, c.Signature, c.PublicKey, strings.Join(c.Standards, ", "))
}
