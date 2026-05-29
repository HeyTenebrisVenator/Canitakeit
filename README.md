# CanITakeIt

A multithreaded CNAME-based subdomain takeover reconnaissance tool.

CanITakeIt analyzes subdomains, resolves CNAME records, and identifies references to third-party services that are commonly associated with subdomain takeover vulnerabilities.

The tool is designed for security researchers, bug bounty hunters, penetration testers, and asset inventory teams who need to quickly identify potentially vulnerable subdomains across large environments.

> **Disclaimer:** A matching CNAME fingerprint does **not** automatically indicate a vulnerability. It only suggests that the target should be investigated further. Always verify findings manually before reporting them.

---

# Features

* Fast multithreaded DNS resolution.
* CNAME record collection and analysis.
* Detection of known takeover-prone services.
* Colored terminal output.
* TXT and CSV export formats.
* Configurable DNS timeout and lifetime values.
* Support for large target lists.
* Deduplication of input targets.
* Detailed result classification.

---

# Supported Providers

CanITakeIt currently detects references to services including:

| Provider              | Fingerprint          |
| --------------------- | -------------------- |
| AWS Elastic Beanstalk | elasticbeanstalk.com |
| AWS S3                | s3.amazonaws.com     |
| Azure App Service     | azurewebsites.net    |
| Azure CloudApp        | cloudapp.net         |
| Azure CDN             | azureedge.net        |
| Bitbucket             | bitbucket.io         |
| Read the Docs         | readthedocs.io       |
| WordPress             | wordpress.com        |
| Surge                 | surge.sh             |
| Strikingly            | s.strikinglydns.com  |
| Discourse             | trydiscourse.com     |
| Help Scout            | helpscoutdocs.com    |
| LaunchRock            | launchrock.com       |
| ReadMe                | readme.io            |
| Uberflip              | uberflip.com         |
| SmartJobBoard         | smartjobboard.com    |

And many others.

---

# Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/canitakeit.git
cd canitakeit
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Or install manually:

```bash
pip install dnspython colorama tabulate
```

---

# Usage

## Basic Scan

```bash
python3 canitakeit.py \
    -i subdomains.txt
```

---

## Increase Worker Threads

```bash
python3 canitakeit.py \
    -i subdomains.txt \
    -t 100
```

---

## Save Results

TXT:

```bash
python3 canitakeit.py \
    -i subdomains.txt \
    -o results.txt
```

CSV:

```bash
python3 canitakeit.py \
    -i subdomains.txt \
    -o results.csv
```

---

## Configure DNS Timeouts

```bash
python3 canitakeit.py \
    -i subdomains.txt \
    --timeout 5 \
    --lifetime 10
```

---

## Disable Colors

```bash
python3 canitakeit.py \
    -i subdomains.txt \
    --no-color
```

---

# Command Line Options

| Option            | Description                      |
| ----------------- | -------------------------------- |
| `-i`, `--input`   | Input file containing subdomains |
| `-t`, `--threads` | Number of worker threads         |
| `-o`, `--output`  | Output file (.txt or .csv)       |
| `--timeout`       | DNS query timeout                |
| `--lifetime`      | DNS resolver lifetime            |
| `--no-color`      | Disable colored output           |

---

# Input File Format

Provide one subdomain per line:

```text
blog.example.com
docs.example.com
old.example.com
staging.example.com
```

Comments are supported:

```text
# Production
app.example.com

# Staging
staging.example.com
```

---

# Example Output

```text
+--------------------+-----------------------------------+------------------------+-------------------+
| Subdomain          | CNAME                             | Provider               | Status            |
+--------------------+-----------------------------------+------------------------+-------------------+
| docs.example.com   | project.readthedocs.io           | Read the Docs          | POSSIBLE TAKEOVER |
| app.example.com    | app.azurewebsites.net            | Azure App Service      | POSSIBLE TAKEOVER |
| www.example.com    | cdn.example.net                  | -                      | SAFE              |
+--------------------+-----------------------------------+------------------------+-------------------+
```

---

# Result Classification

| Status            | Description                                     |
| ----------------- | ----------------------------------------------- |
| POSSIBLE_TAKEOVER | CNAME points to a known takeover-prone provider |
| SAFE              | No known takeover fingerprint detected          |
| NO_CNAME          | No CNAME record found                           |
| NXDOMAIN          | Domain does not exist                           |
| TIMEOUT           | DNS query timed out                             |
| NO_NAMESERVERS    | No responsive nameservers                       |
| ERROR             | Unexpected error occurred                       |

---

# Typical Bug Bounty Workflow

```text
Subdomain Enumeration
        │
        ▼
DNS Validation
        │
        ▼
CanITakeIt
        │
        ▼
Manual Verification
        │
        ▼
Subdomain Takeover Testing
        │
        ▼
Responsible Disclosure
```

---

# Important Notes

CanITakeIt does **not** attempt to claim resources or exploit services.

The tool only identifies potentially interesting targets based on DNS fingerprints.

A valid takeover usually requires additional verification, such as:

* Service-specific error messages.
* Unclaimed resources.
* Missing DNS targets.
* Provider-specific takeover conditions.

Always perform manual validation before reporting a vulnerability.

---

# Future Improvements

Planned features include:

* HTTP verification of takeover candidates.
* Automatic fingerprint updates.
* Service-specific verification modules.
* JSON output format.
* HTML reporting.
* Integration with reconnaissance pipelines.
* Custom fingerprint databases.
* Screenshot collection for takeover candidates.
* API mode for automation.

---

# Why "CanITakeIt"?

The name reflects the core question every security researcher asks when discovering an abandoned third-party DNS reference:

> **"Can I take it?"**

CanITakeIt helps answer that question by quickly identifying subdomains that may warrant deeper takeover investigation.

---

# Author

Arthur Witt

Built for bug bounty hunting, attack surface management, penetration testing, and security research.
