// Command presets demonstrates policy presets: NIST, OWASP, PCI-DSS, etc.
//
// Run: go run ./examples/presets
package main

import (
	"fmt"
	"log"

	"github.com/rafaelsanzio/passcheck"
)

func main() {
	password := "MyP@ssw0rd2024"

	presets := []struct {
		name string
		cfg  passcheck.Config
	}{
		{"NIST (length over composition)", passcheck.NISTConfig()},
		{"UserFriendly", passcheck.UserFriendlyConfig()},
		{"OWASP", passcheck.OWASPConfig()},
		{"PCI-DSS", passcheck.PCIDSSConfig()},
		{"Enterprise", passcheck.EnterpriseConfig()},
	}

	for _, p := range presets {
		result, err := passcheck.CheckWithConfig(password, p.cfg)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%-25s score=%3d  verdict=%s\n", p.name+":", result.Score, result.Verdict)
	}
}
