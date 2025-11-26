#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

if [ $# -ne 3 ]; then
    echo "Usage: $0 <targets.txt> <username> <password>"
    exit 1
fi

inputfile="$1"
user="$2"
pass="$3"
base_dir="$(pwd)"

log() { echo -e "\n[+] $1"; }

# generic logger
run_and_log() {
    local cmd="$1"
    local out="$2"

    mkdir -p "$(dirname "$out")"

    {
        echo "# COMMAND RAN: $cmd"
        echo "# RUN AT: $(date --iso-8601=seconds)"
        echo "--------------------------------------------------"
    } > "$out"

    # never kill the whole script if this fails
    bash -lc "$cmd" >> "$out" 2>&1 || true
}

while read -r ip; do
    [ -z "$ip" ] && continue

    log "Target: $ip"

    ip_dir="$base_dir/$ip"
    port_dir="$ip_dir/port-enum"
    raw_dir="$port_dir/.raw"
    mkdir -p "$port_dir" "$raw_dir"

    # per-IP vars derived later (LDAP, DNS)
    zone=""
    base_dn=""

    ############################################################
    # 1) RUSTSCAN (TCP) — same style as oscp_enum.sh
    ############################################################
    raw_rust="$raw_dir/rust.txt"
    rust_cmd="rust -a \"$ip\" -- -A -v -oN \"$raw_rust\""

    log "Running RustScan on $ip..."
    # RustScan writes REAL output only to .raw/rust.txt
    bash -lc "$rust_cmd" >/dev/null 2>&1 || true

    # pretty rust.txt (single copy, with header)
    rust_out="$port_dir/rust.txt"
    {
        echo "# COMMAND RAN: $rust_cmd"
        echo "# RUN AT: $(date --iso-8601=seconds)"
        echo "--------------------------------------------------"
        cat "$raw_rust" 2>/dev/null || true
    } > "$rust_out"

    ############################################################
    # 2) UDP TOP-100 (nmap) — same style as oscp_enum.sh
    ############################################################
    raw_udp="$raw_dir/udp.txt"
    udp_cmd="nmap -Pn -n \"$ip\" -sU --top-ports 100 -v -oN \"$raw_udp\""

    log "Running UDP top-100 scan on $ip..."
    bash -lc "$udp_cmd" >/dev/null 2>&1 || true

    udp_out="$port_dir/udp.txt"
    {
        echo "# COMMAND RAN: $udp_cmd"
        echo "# RUN AT: $(date --iso-8601=seconds)"
        echo "--------------------------------------------------"
        cat "$raw_udp" 2>/dev/null || true
    } > "$udp_out"

    ############################################################
    # 3) TCP / UDP port lists (CSV, no dups)
    ############################################################
    tcp_ports_file="$port_dir/tcp_open_ports.txt"
    tcp_cmd="grep -Eo '^[0-9]+/tcp\\s+open' \"$raw_rust\" 2>/dev/null | grep -Eo '^[0-9]+' | sort -nu | paste -sd, -"
    run_and_log "$tcp_cmd" "$tcp_ports_file"

    udp_ports_file="$port_dir/udp_open_ports.txt"
    udp_cmd="grep -Eo '^[0-9]+/udp\\s+open' \"$raw_udp\" 2>/dev/null | grep -Eo '^[0-9]+' | sort -nu | paste -sd, -"
    run_and_log "$udp_cmd" "$udp_ports_file"

    ############################################################
    # 4) Parse services from rust (for feature detection)
    ############################################################
    services=$(grep -Eo '^[0-9]+/tcp\s+open\s+\S+' "$raw_rust" 2>/dev/null | awk '{print $1 "|" $3}')
    rust_full="$(cat "$raw_rust" 2>/dev/null || true)"
    udp_full="$(cat "$raw_udp" 2>/dev/null || true)"  # maybe useful for DNS over UDP

    ############################################################
    # 5) SMB ENUM (with creds + anon + nxc)
    ############################################################
    if echo "$services" | grep -E '\|smb|\|microsoft-ds|\|netbios' >/dev/null \
       || echo "$rust_full" | grep -E '^445/tcp\s+open|^139/tcp\s+open' >/dev/null; then

        smb_dir="$ip_dir/smb"
        mkdir -p "$smb_dir"
        log "Enumerating SMB on $ip (anon + auth + nxc)"

        # enum4linux-ng (authenticated)
        run_and_log "enum4linux-ng -u \"$user\" -p \"$pass\" \"$ip\"" "$smb_dir/enum4linux-ng-auth.txt"

        # smbclient (authenticated)
        run_and_log "echo \"exit\" | smbclient -L \"//$ip/\" -U \"$user\" --password=\"$pass\"" "$smb_dir/smbclient-auth.txt"

        # NetExec (nxc) SMB --users
        run_and_log "nxc smb \"$ip\" -u \"$user\" -p \"$pass\" --users" "$smb_dir/nxc-users.txt"

        # Clean user list from nxc output (between header and 'Enumerated' line)
        run_and_log "awk '/-Username-/{start=1; next} /Enumerated/{start=0} start {print \$5}' \"$smb_dir/nxc-users.txt\" | sort -u" "$smb_dir/nxc-users-list.txt"
    fi

    ############################################################
    # 6) RPC ENUM (prefer creds)
    ############################################################
    if echo "$services" | grep -E '\|rpc|\|msrpc' >/dev/null \
       || echo "$rust_full" | grep -E '^135/tcp\s+open' >/dev/null; then

        rpc_dir="$ip_dir/rpc"
        mkdir -p "$rpc_dir"
        log "RPC found — enumerating users (with creds, plus anon)"

        # Authenticated RPC enum
        run_and_log "rpcclient -U \"$user\" --password=\"$pass\" \"$ip\" -c enumdomusers" "$rpc_dir/rpc-users-auth.txt"

        # Extract user list from authenticated output
        run_and_log "grep -oP '(?<=user:\\[)[^\\]]+' \"$rpc_dir/rpc-users-auth.txt\" | sort -u" "$rpc_dir/rpc-users-list.txt"

    fi

    ############################################################
    # 7) LDAP ENUM (rootDSE → base DN → users/groups/all)
    ############################################################
    if echo "$services" | grep -E '\|ldap' >/dev/null \
       || echo "$rust_full" | grep -E '^389/tcp\s+open|^636/tcp\s+open' >/dev/null; then

        ldap_dir="$ip_dir/ldap"
        mkdir -p "$ldap_dir"
        log "LDAP detected — grabbing rootDSE and base DN"

        # rootDSE (no base yet)
        run_and_log "ldapsearch -x -H ldap://$ip -s base" "$ldap_dir/rootdse.txt"

        # Extract defaultNamingContext (base DN)
        if grep -qi '^defaultNamingContext:' "$ldap_dir/rootdse.txt"; then
            base_dn=$(grep -i '^defaultNamingContext:' "$ldap_dir/rootdse.txt" \
                        | head -n1 \
                        | cut -d: -f2- \
                        | xargs)
            echo "$base_dn" > "$ldap_dir/base_dn.txt"
        fi

        if [ -n "${base_dn:-}" ]; then
            log "LDAP base DN: $base_dn"

            # Build FQDN zone from base DN (e.g. DC=internal,DC=local -> internal.local)
            zone=$(echo "$base_dn" | tr -d ' ' | sed -E 's/DC=//g; s/,/./g')
            echo "$zone" > "$ldap_dir/domain.txt"

            # Full dump (all objects)
            run_and_log "ldapsearch -x -H ldap://$ip -b \"$base_dn\" \"(objectClass=*)\"" "$ldap_dir/all.txt"

            # Users only
            run_and_log "ldapsearch -x -H ldap://$ip -b \"$base_dn\" \"(objectClass=person)\"" "$ldap_dir/users.txt"

        else
            log "Could not determine defaultNamingContext from LDAP rootDSE on $ip"
        fi
    fi

    ############################################################
    # 8) DNS ENUM / zone transfer (use LDAP-derived zone if we have it)
    ############################################################
    if echo "$services" | grep -E '\|domain' >/dev/null \
       || echo "$rust_full" | grep -E '^53/tcp\s+open' >/dev/null \
       || echo "$udp_full"  | grep -E '^53/udp\s+open' >/dev/null; then

        dns_dir="$ip_dir/dns"
        mkdir -p "$dns_dir"

        if [ -n "${zone:-}" ]; then
            log "DNS detected — attempting AXFR for zone '$zone'"
            run_and_log "dig @\"$ip\" axfr \"$zone\"" "$dns_dir/zone-transfer-$zone.txt"
        else
            log "DNS detected — no zone from LDAP, attempting generic AXFR"
            run_and_log "dig axfr @\"$ip\"" "$dns_dir/zone-transfer.txt"
        fi
    fi

    log "✅ Done with $ip"

done < "$inputfile"

echo -e "\n🧠 AD enum complete. All results saved under: $(pwd)"