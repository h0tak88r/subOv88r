# SubOv88r

A simple Go tool for analyzing subdomains for subdomain takeover vulnerability, especially in Azure services.

## Features
- Checks CNAME records for Azure-related domains (e.g., cloudapp.net, azurewebsites.net, cloudapp.azure.com, trafficmanager.net)
- Detects NXDOMAIN status for possible takeovers
- Supports colored output and Azure-only filtering

## Installation

You can build from source or install via Go:

```bash
go install github.com/h0tak88r/subov88r@latest
```
Or build manually:
```bash
go build -o subov88r subov88r.go
```

## Usage

```bash
# Basic usage:
./subov88r -f subdomains.txt

# Only show possible Azure takeovers (suppress info lines):
./subov88r -f subdomains.txt -asto

# Disable colored output (for scripting):
./subov88r -f subdomains.txt -nc
```

### Options
- `-f <file>`: Path to the subdomains file (required)
- `-asto`: Only print possible Azure subdomain takeovers (suppress [INFO] lines)
- `-nc`: Disable colored output (plain text output, suitable for scripts)

### Output Format
- Vulnerable Azure subdomain takeovers:
  - Colored: `[VULNERABLE] [SUBDOMAIN:sub.example.com] [CNAME:sub.example.com.cloudapp.net] [STATUS:NXDOMAIN]`
  - No color (`-nc`): `[VULNERABLE] [SUBDOMAIN:sub.example.com] [CNAME:sub.example.com.cloudapp.net] [STATUS:NXDOMAIN]`
- Informational (non-vulnerable) lines (only shown if `-asto` is not set):
  - Colored: `[INFO] [SUBDOMAIN:sub.example.com] [CNAME:sub.example.com.trafficmanager.net] [STATUS:NOERROR]`
  - No color (`-nc`): `[INFO] [SUBDOMAIN:sub.example.com] [CNAME:sub.example.com.trafficmanager.net] [STATUS:NOERROR]`

### Example Output
```
[VULNERABLE] [SUBDOMAIN:www.vulnerable.example.com] [CNAME:www.vulnerable.example.com.cloudapp.net] [STATUS:NXDOMAIN]
[INFO] [SUBDOMAIN:test.example.com] [CNAME:test.example.com.trafficmanager.net] [STATUS:NOERROR]
```

The tool is used automatically by the main autoAr.sh script for Azure takeover checks, but you can run it manually for custom lists.
