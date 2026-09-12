# PipeWrench

PipeWrench is a local, read-only operations console for Cisco Secure Firewall ASA headends. It uses Cisco's ASA HTTP interface for automation on port `2002` and sends the required `User-Agent: ASDM` header.

## First run

1. Add one headend short name per line to `headends.txt`. Do not include `:2002`.
2. Create `un.txt` and put only your current username in it.
3. Create `pw.txt` and put only your current password in it.
4. On Windows, double-click `Start-PipeWrench.bat`. On macOS or Linux, run `./start.sh`.
5. Open <http://127.0.0.1:8765> if it does not open automatically.

Credentials are read again for every ASA request. Update `pw.txt` after a Delinea password rotation; PipeWrench does not need to be restarted.

## Device lists

- `headends.txt` is the master list and can be kept in the repository.
- Headends added in the UI are saved to `headends.local.txt`.
- `headends.local.txt`, `un.txt`, and `pw.txt` are excluded from Git.
- The UI merges and deduplicates both headend lists.

## Health and standards review

The health snapshot retrieves hostname, version and uptime, failover, interface, CPU, memory, VPN-session, and clock data. Common values such as uptime, ASA version, CPU, active VPN sessions, supported VPN capacity, and VPN load are extracted into metric cards while the complete command output remains available underneath.

The standards review retrieves focused running-configuration sections for AAA, SNMP, group policies, SSL, SSH, WebVPN, IP, logging, banners, management access, ACLs, MTU, ASDM, crypto, names, address assignment, pools, DNS, usernames, domain name, HTTP, ICMP, and tunnel groups. It also retrieves detailed clock and VPN capacity/session information. Common password, secret, pre-shared-key, and SNMP community values are masked before output reaches the browser.

## Management certificates

Certificate verification is disabled by default because the internal management short names do not match the VPN-facing certificate names, and some ASA management listeners present self-signed certificates. This exception is limited to HTTPS connections made by PipeWrench; it does not change Windows, browser, or Python trust settings system-wide.

If management certificates are later issued for the internal names, set `verify_tls` to `true`. A private CA bundle can be supplied through `ca_bundle` in `config.json`.

## Safety boundary

Version 0.1 exposes only named inspection actions. It does not accept arbitrary ASA commands from the browser and it does not contain configuration-write routes.
