package main

import (
	"recon/internal/suzu"
)

func main() {
	// CLI entry point for wordlist parsing
	// Reads JSON config from stdin, outputs JSON result to stdout
	suzu.ParseWordlistJSON()
}
