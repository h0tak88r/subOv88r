package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// ANSI color codes
const (
	Red   = "\033[0;31m"
	Blue  = "\033[0;34m"
	Green = "\033[0;32m"
	NC    = "\033[0m" // No Color
)

func main() {
	// Parse command-line arguments
	filepath := flag.String("f", "", "Path to the subdomains file")
	azureOnly := flag.Bool("asto", false, "Only check for Azure subdomain takeover")
	noColor := flag.Bool("nc", false, "Disable colored output")
	flag.Parse()

	// Check for provided subdomains file
	if *filepath == "" {
		fmt.Println("Usage: subov88r -f subdomains.txt [-asto] [-nc]")
		os.Exit(88)
	}

	// Open subdomains file
	file, err := os.Open(*filepath)
	if err != nil {
		fmt.Println("Error while opening file:", err)
		os.Exit(1)
	}
	defer file.Close()

	// Loop over the list of subdomains
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		subdomain := scanner.Text()

		// Get the CNAME record for the subdomain
		cname, _ := net.LookupCNAME(subdomain)

		// Skip if CNAME is empty
		if cname == "" {
			continue
		}

		// Get the status of the subdomain
		status, err := getStatus(subdomain)
		if err != nil {
			fmt.Printf("Error getting status for %s: %v\n", subdomain, err)
			continue
		}

		isVuln := azureSTO(cname, status)

		if isVuln {
			if *noColor {
				fmt.Printf("[VULNERABLE] [SUBDOMAIN:%s] [CNAME:%s] [STATUS:%s]\n", subdomain, cname, status)
			} else {
				fmt.Printf("%s[VULNERABLE]%s [SUBDOMAIN:%s%s%s] [CNAME:%s%s%s] [STATUS:%s%s%s]\n",
					Red, NC, Red, subdomain, NC, Blue, cname, NC, Green, status, NC)
			}
			continue
		}

		// Print results with ANSI colors if not Azure-only mode and colors enabled
		if !*azureOnly {
			if *noColor {
				fmt.Printf("[INFO] [SUBDOMAIN:%s] [CNAME:%s] [STATUS:%s]\n",
					subdomain, cname, status)
			} else {
				fmt.Printf("%s[INFO]%s [SUBDOMAIN:%s%s%s] [CNAME:%s%s%s] [STATUS:%s%s%s]\n",
					Blue, NC, Blue, subdomain, NC, Blue, cname, NC, Green, status, NC)
			}
		}
	}
}

// getStatus gets the status from the dig output
func getStatus(subdomain string) (string, error) {
	cmd := exec.Command("dig", subdomain)
	digResult, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}

	digOutput := string(digResult)
	status := ""
	lines := strings.Split(digOutput, "\n")
	for _, line := range lines {
		if strings.Contains(line, "status:") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				status = fields[5]
				break
			}
		}
	}
	return status, nil
}

// function that check for subdomain takeover in azure services
func azureSTO(cname string, status string) bool {
	azureRegex := regexp.MustCompile(`(?i)^(?:[a-z0-9-]+\.)?(?:cloudapp\.net|azurewebsites\.net|cloudapp\.azure\.com|trafficmanager\.net)$`)

	if strings.Contains(status, "NXDOMAIN") && azureRegex.MatchString(cname) {
		return true
	}
	return false
}
