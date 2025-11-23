# linkedin

A Go library to fetch LinkedIn user profile data using authenticated session cookies from your browser.

## Features

- **Minimal cookie usage**: In practice, only `li_at` cookie is required
- **Automatic cookie extraction** from Firefox/Firefox Developer Edition using [kooky](https://github.com/browserutils/kooky)
- **Command-line tool** for quick profile lookups
- **Clean API** following Go best practices
- **Context-aware** with structured logging
- **Debug mode** to inspect cookies and requests
- **Handles modern LinkedIn SDUI** (Server-Driven UI) format

## Installation

### As a library:
```bash
go get github.com/tstromberg/linkedin
```

### As a command-line tool:
```bash
go install github.com/tstromberg/linkedin/cmd/linkedin@latest
```

Or build from source:
```bash
make build
./bin/linkedin <profile-url>
```

## Command-Line Usage

```bash
# Basic usage
linkedin https://www.linkedin.com/in/thomas-str%C3%B6mberg-9977261/

# With verbose logging
linkedin -v https://www.linkedin.com/in/thomas-str%C3%B6mberg-9977261/

# With debug mode (shows cookies and requests)
linkedin -debug https://www.linkedin.com/in/thomas-str%C3%B6mberg-9977261/
```

Output:
```
LinkedIn Profile
================
Name:     Thomas Strömberg
Headline: Software Engineer at Google
Employer: Google
Location: Mountain View, CA
URL:      https://www.linkedin.com/in/thomas-strömberg-9977261/
```

## Library Usage

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/tstromberg/linkedin"
)

func main() {
    ctx := context.Background()

    client, err := linkedin.New(ctx)
    if err != nil {
        log.Fatal(err)
    }

    // Optional: enable debug mode
    // client.EnableDebug()

    profile, err := client.FetchProfile(ctx, "https://www.linkedin.com/in/thomas-strömberg-9977261/")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Name: %s\n", profile.Name)
    fmt.Printf("Employer: %s\n", profile.CurrentEmployer)
}
```

## Minimal Cookie Requirements

After testing, LinkedIn profile fetching requires only **4 cookies**:

1. **`li_at`** - Authentication token (REQUIRED)
2. **`JSESSIONID`** - Session ID (REQUIRED)
3. **`lidc`** - Data center routing (REQUIRED)
4. **`bcookie`** - Browser cookie (may be required)

The library automatically filters to use only these essential cookies, ignoring all others from your browser.

## Using Environment Variables

Instead of extracting cookies from your browser, you can set them as environment variables:

```bash
export LINKEDIN_LI_AT="your-li_at-cookie-value"
export LINKEDIN_JSESSIONID="your-jsessionid-value"
export LINKEDIN_LIDC="your-lidc-value"
export LINKEDIN_BCOOKIE="your-bcookie-value"

linkedin https://www.linkedin.com/in/...
```

Environment variables take precedence over browser cookies. This is useful for:
- CI/CD pipelines
- Docker containers
- Serverless functions
- Any environment without a browser

## Testing Cookie Combinations

To determine the minimum required cookies for your LinkedIn account:

```bash
make test-cookies URL=https://www.linkedin.com/in/your-profile/
```

Or build and run directly:

```bash
go build -o bin/test-cookies ./cmd/test-cookies
./bin/test-cookies -url https://www.linkedin.com/in/your-profile/
```

This will test various cookie combinations and report which ones work:
- `li_at` only
- `li_at` + `JSESSIONID`
- `li_at` + `JSESSIONID` + `lidc`
- All 4 cookies
- And various other combinations

## Requirements

- **Option 1**: Logged into LinkedIn in Firefox (for automatic cookie extraction)
- **Option 2**: LinkedIn cookies set as environment variables
- LinkedIn cookies must be valid and not expired

## How It Works

1. Uses `kooky` to extract LinkedIn session cookies from Firefox
2. Filters to only essential cookies (li_at, JSESSIONID, lidc, bcookie)
3. Makes authenticated HTTP requests to LinkedIn profile pages with proper Firefox headers
4. Parses embedded Voyager API JSON data and HTML meta tags
5. Returns structured profile data

## Development

```bash
# Run tests
make test

# Build the CLI tool
make build

# Run with arguments
make run ARGS="-v https://www.linkedin.com/in/..."

# Run linter (requires golangci-lint)
make lint
```

## Security Note

This library accesses your browser's cookies to authenticate with LinkedIn. Only use with profiles you have permission to access.
