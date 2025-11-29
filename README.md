<p align="center">
  <img src="assets/dragon.png" width="500">
</p>

# DragonMap

`dragon-map.sh` is a Bash script designed for **Active Directory (AD) credentialed enumeration** in an assumed-breach scenario.  
It performs high-signal enumeration against SMB, RPC, LDAP, DNS, and related AD services using valid credentials, 
and saves all output in an organized per-host folder structure with timestamps and full command history.

> **Use only on systems you own or have explicit permission to test.**

## Features

- Reads a list of AD hosts from a text file (one IP per line).
- Performs port discovery using:
  - **RustScan** (TCP)
  - **Nmap** (top 100 UDP ports)
- Generates comma-separated lists of open TCP/UDP ports.
- Automatically detects key AD services and performs deep enumeration:
  - **SMB Enumeration** (authenticated + anonymous):
    - `enum4linux-ng`
    - `smbclient` (auth)
    - `nxc smb --users`
    - Automatic extraction of user lists from NetExec output
  - **RPC Enumeration**:
    - Authenticated `rpcclient enumdomusers`
    - Extraction of valid AD usernames
  - **LDAP Enumeration**:
    - RootDSE query
    - Automatic extraction of `defaultNamingContext`
    - Domain reconstruction (DC=corp,DC=local → corp.local)
    - Dump of all LDAP objects
    - Dump of LDAP users
  - **DNS Enumeration**:
    - Attempts zone transfer using LDAP-derived domain (AXFR)
    - Falls back to generic zone-transfer attempts if domain is unknown
- Every command is logged with:
  - the **exact command** executed
  - a **timestamp**
  - **stdout + stderr** captured in the output file
- Safe enumeration flow — failures in individual tools do not terminate the script.

## Requirements

Tested primarily on **Kali Linux**. You’ll need:

- `bash`
- `rustscan` (aliased as `rust` — adjust if needed)
- `nmap`
- `enum4linux-ng`
- `smbclient`
- `nxc` (NetExec)
- `rpcclient`
- `ldapsearch`
- `dig`
- `awk`, `grep`, `sed`, `cut`

Ensure your PATH includes these tools.

## Usage

```bash
chmod +x dragon-map.sh

#targets.txt: one IP per line
cat targets.txt
192.168.1.10
192.168.1.20

#Run with credentials from the directory where you want results saved
./dragon-map.sh targets.txt 'username' 'password'
```

For each target X.X.X.X, the script creates:

```bash
X.X.X.X/
├── port-enum/
│   ├── rust.txt
│   ├── udp.txt
│   ├── tcp_open_ports.txt
│   ├── udp_open_ports.txt
│   └── .raw/
│       ├── rust.txt
│       └── udp.txt
├── smb/
│   ├── enum4linux-ng-auth.txt
│   ├── smbclient-auth.txt
│   ├── nxc-users.txt
│   └── nxc-users-list.txt
├── rpc/
│   ├── rpc-users-auth.txt
│   └── rpc-users-list.txt
├── ldap/
│   ├── rootdse.txt
│   ├── base_dn.txt
│   ├── domain.txt
│   ├── all.txt
│   └── users.txt
└── dns/
    ├── zone-transfer.txt
    └── zone-transfer-<domain>.txt
```

## How Output Files Are Structured

Every generated `.txt` file starts with metadata:

COMMAND RAN: <exact command executed>  
RUN AT: <ISO-8601 timestamp>  

This makes it easy to replay, debug, or modify commands later.

## Notes

- The script uses `set -euo pipefail`, but enumeration commands are wrapped in `|| true`
  to prevent tool failures from stopping the run.
- RustScan is invoked as `rust`; change to `rustscan` if needed.
- LDAP base DN and domain names are extracted automatically when possible.
- DNS zone transfers are attempted only if port 53 is open.

## Disclaimer

This tool is intended **only for legal penetration testing and educational research**.  
Do **NOT** use it on systems without explicit, written authorization.  
You are fully responsible for how you use this script.
