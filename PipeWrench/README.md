# PipeWrench

PipeWrench is a local, read-only operations console for Cisco Secure Firewall ASA headends. It uses Cisco's ASA HTTP interface for automation on port `2002` and sends the required `User-Agent: ASDM` header.

## First run

1. Add one headend short name per line to `headends.txt`. Do not include `:2002`.
2. Create `~/creds/un.txt` and put only your current username in it.
3. Create `~/creds/pw.txt` and put only your current password in it.
4. On Windows, double-click `Start-PipeWrench.bat`. On macOS or Linux, run `./start.sh`.
5. Open <http://127.0.0.1:8765> if it does not open automatically.

Credentials are read again for every ASA request. Update `~/creds/pw.txt` after a Delinea password rotation; PipeWrench does not need to be restarted. If the credential directory moves, change the single `CREDENTIAL_DIR` line in `VARS`.

## Device lists

- `headends.txt` is the master list and can be kept in the repository.
- Headends added in the UI are saved to `headends.local.txt`.
- `headends.local.txt`, `un.txt`, and `pw.txt` are excluded from Git.
- The UI merges and deduplicates both headend lists.

## Health and standards review

The health snapshot retrieves hostname, version and uptime, failover, interface, CPU, memory, VPN-session, and clock data. Common values such as uptime, ASA version, CPU, active VPN sessions, supported VPN capacity, and VPN load are extracted into metric cards while the complete command output remains available underneath.

The standards review retrieves focused running-configuration sections for AAA, SNMP, group policies, SSL, SSH, WebVPN, IP, logging, banners, management access, ACLs, MTU, ASDM, crypto, names, address assignment, pools, DNS, usernames, domain name, HTTP, ICMP, tunnel groups, and configured VPN session limits. It also retrieves detailed clock and VPN capacity/session information. Common password, secret, pre-shared-key, and SNMP community values are masked before output reaches the browser.

Each standards result tallies the inclusive address ranges from every `ip local pool`, the provisioned `Device Total VPN Capacity`, and the configured `vpn-sessiondb max-anyconnect-premium-or-essentials-limit`. The effective session ceiling is the lowest of those three values. Overlapping pool ranges are counted once and reported for review.

## Snapshots and gold profiles

After an inspection, choose **Save snapshot** to write a timestamped JSON record under `archives/`. The filename begins with UTC `YYYYMMDDHHMMSS`, and `snapshot_version` is the first field in the document. These files are intentionally suitable for Git archival.

Open a prior result from **Past results**. A yellow clock banner remains visible whenever historical data is on screen. A saved standards snapshot can be promoted to a gold profile using a platform family (such as `41xx` or `42xx`) and a location (such as `amer` or `emea`). Gold records live under `baselines/` and can be compared with any saved result.

Gold comparison is section-aware. Device-specific addresses, SNMP engine IDs, trustpoint names, and VPN listener hostnames are parameterized where appropriate. Split-tunnel IPs and domains are compared as exact unordered sets. Large or volatile sections such as certificates, crypto, sessions, clocks, full ACL output, tunnel groups, and group policies use lint rules instead of raw equality.

## Multi-headend walks

Expand **Multi-headend walk**, select headends, and optionally select a platform/location gold profile. PipeWrench runs up to `batch_workers` headends concurrently, automatically archives each result, and writes progress under `batches/`. Leave the PipeWrench server running; the browser can be reopened after the work finishes and the saved results will still be available.

## On-demand tools

Open the **Tools** tab and run **Service-wide VPN capacity** when a fresh capacity inventory is needed. PipeWrench queries every configured headend for IP local pools, external DHCP assignment, provisioned VPN capacity, the configured AnyConnect session limit, and current AnyConnect sessions. It classifies address assignment as Local, DHCP, Mixed, or Unknown. Local ranges are counted exactly (with overlaps removed); external DHCP servers and network scopes are called out, but their capacity remains unknown until an authoritative DHCP/IPAM source supplies scope bounds and exclusions. The report shows per-headend values plus service-wide totals and saves reports under `capacity-reports/` so interrupted or previous runs can be reopened.

## Built-in standards findings

Standards reviews currently flag:

- missing required settings for AAA, SNMP, SSL, SSH, WebVPN, interfaces, logging, ASDM, DNS, HTTP, MTU, ICMP, crypto, and other focused sections defined in `lint_rules.json`;
- a missing or incorrectly configured `ec_T3ch1_y` PBKDF2/privilege-15 fallback account, any additional local usernames, TACACS without an `Inside` host, or missing TACACS-first/LOCAL-fallback management authentication, authorization, and accounting lines;
- missing IP or dynamic split-tunnel assignments under `DfltGrpPolicy`;
- missing or malformed split-tunnel version markers and duplicate/invalid entries;
- IP local pool ranges without a covering `Null0` route;
- tunnel groups that reference nonexistent group policies;
- expired certificates referenced by SSL, crypto, or WebVPN configuration;
- expired certificates that appear unused and may be cleanup candidates.

The IP split list accepts an `update:<date>` remark. The dynamic split list expects exactly one `dd.mmm.yy.optum.com` marker as its first domain entry. Until that marker is deployed, PipeWrench reports a review warning rather than a command failure. Edit `lint_rules.json` to version-control required section settings without changing Python code.

Certificate removal is never automatic. ASA output can vary by release, so validate reported usage against the full configuration before removing a trustpoint.

## Management certificates

Certificate verification is disabled by default because the internal management short names do not match the VPN-facing certificate names, and some ASA management listeners present self-signed certificates. This exception is limited to HTTPS connections made by PipeWrench; it does not change Windows, browser, or Python trust settings system-wide.

If management certificates are later issued for the internal names, set `verify_tls` to `true`. A private CA bundle can be supplied through `ca_bundle` in `config.json`.

## Safety boundary

Version 0.4 exposes only named inspection actions. It does not accept arbitrary ASA commands from the browser and it does not contain configuration-write routes.
