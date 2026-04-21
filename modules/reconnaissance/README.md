# Reconnaissance Modules

## System packages to install first

On Ubuntu/Debian, install the native tools used by these modules:

```bash
sudo apt update
sudo apt install -y nmap whois dnsutils
```

Optional but useful:

```bash
sudo apt install -y golang-go
```

`subdomain_lookup.py` expects the `subfinder` binary in your `PATH`. It is usually installed separately from Go, not from Python. If it is not available through your distro packages, install it from ProjectDiscovery's release or Go install instructions.

## Python dependencies

Install the Python packages from `requirements.txt` in the project root:

```bash
pip install -r requirements.txt
```

## Modules

### `dns_lookup.py`

Resolves DNS records for a domain.

Usage:

```python
from reconnaissance.dns_lookup import ns_lookup

print(ns_lookup("example.com"))
```

Returns a list of resolved addresses when available.

### `ip_lookup.py`

Looks up geolocation and network info for an IP address using `ipinfo.io`.

Usage:

```python
from reconnaissance.ip_lookup import ip_lookup

print(ip_lookup("8.8.8.8"))
```

Returns a dictionary with fields like `IP`, `City`, `Country`, and `Organization`.

### `whois_lookup.py`

Fetches WHOIS information for a domain.

Usage:

```python
from reconnaissance.whois_lookup import whois_lookup

print(whois_lookup("example.com"))
```

Returns the WHOIS object/result for the domain.

### `get_ip.py`

Gets IP/geo enrichment for a domain using the `GET_IP_KEY` API key from your `.env` file.

Usage:

```python
from reconnaissance.get_ip import get_ip_info

print(get_ip_info("example.com"))
```

Set this in `.env` first:

```bash
GET_IP_KEY=your_api_key_here
```

### `subdomain_lookup.py`

Enumerates subdomains with `subfinder`, checks which ones resolve, and returns the most relevant results.

Usage:

```python
from reconnaissance.subdomain_lookup import subdomain_lookup

print(subdomain_lookup("example.com"))
```

Returns a list of dictionaries like:

```python
{"subdomain": "api.example.com", "ip": "93.184.216.34", "score": 10}
```

### `os_fingerprint.py`

Runs Nmap OS detection and returns structured OS fingerprint data.

Usage:

```python
from reconnaissance.os_fingerprint import os_fingerprint_lookup

print(os_fingerprint_lookup("192.168.1.1"))
print(os_fingerprint_lookup("example.com"))
```

Requires the `nmap` binary from `apt` and the `python-nmap` package.

## Notes

- `nmap`, `whois`, and `dnsutils` are system tools, so install them with `sudo apt`.
- `subfinder` is an external binary, not a Python package.
- `sqlite3` is included with Python, so no extra system install is needed.
- The modules are designed to be imported by `modules/recon.py` and the CLI.
