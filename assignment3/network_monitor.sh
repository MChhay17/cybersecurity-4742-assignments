#!/bin/bash

subnet="192.168.56.1-120"
output_dir="/home/kali/Documents/assignment3/scans"
log_file="/home/kali/Documents/assignment3/log.txt"

timestamp=$(date +"%Y-%m-%d_%H-%M")
scan_file="$output_dir/scan_$timestamp.txt"
current_state="$output_dir/current_state.txt"
previous_state="$output_dir/previous_state.txt"

ports="21,22,23,25,53,80,111,139,445,512,513,514,1099,1524,2049,3306,5432,5900,6000,6200,6667,8009,8080,8180"

scan_network() {
    /bin/mkdir -p "$output_dir"
    /usr/bin/nmap -sS -Pn -n -T4 --max-retries 1 --host-timeout 60s -p "$ports" "$subnet" --open -oG "$scan_file"
}

parse_scan_results() {
    /usr/bin/awk '
    /Ports:/ {
        ip=$2
        split($0,a,"Ports: ")
        split(a[2],ports,", ")
        printf "%s -> ", ip
        first=1
        for (i=1; i<=length(ports); i++) {
            split(ports[i],p,"/")
            if (p[2] == "open") {
                if (first == 1) {
                    printf p[1]
                    first=0
                } else {
                    printf ", " p[1]
                }
            }
        }
        printf "\n"
    }' "$scan_file" | /usr/bin/sort > "$current_state"
}

detect_changes() {
    changes=""

    if [ ! -f "$previous_state" ]; then
        changes="INITIAL"
        return
    fi

    while read -r line; do
        ip=$(echo "$line" | awk '{print $1}')
        ports_now=$(echo "$line" | cut -d'>' -f2 | xargs)

        if ! grep -q "^$ip" "$previous_state"; then
            changes="$changes
+ New host: $ip
    Open ports: $ports_now"
        else
            old_ports=$(grep "^$ip" "$previous_state" | cut -d'>' -f2 | xargs)

            for port in $(echo "$ports_now" | tr ',' ' '); do
                if ! echo "$old_ports" | grep -qw "$port"; then
                    changes="$changes
+ $ip: Port $port opened"
                fi
            done
        fi
    done < "$current_state"

    while read -r line; do
        ip=$(echo "$line" | awk '{print $1}')
        old_ports=$(echo "$line" | cut -d'>' -f2 | xargs)

        if grep -q "^$ip" "$current_state"; then
            ports_now=$(grep "^$ip" "$current_state" | cut -d'>' -f2 | xargs)

            for port in $(echo "$old_ports" | tr ',' ' '); do
                if ! echo "$ports_now" | grep -qw "$port"; then
                    changes="$changes
- $ip: Port $port closed"
                fi
            done
        else
            for port in $(echo "$old_ports" | tr ',' ' '); do
                changes="$changes
- $ip: Port $port closed"
            done
        fi
    done < "$previous_state"
}

log_changes() {
    time_now=$(date '+%Y-%m-%d %H:%M')

    if [ "$changes" = "INITIAL" ]; then
        echo "[$time_now] Initial scan:" >> "$log_file"
        cat "$current_state" >> "$log_file"
        echo "" >> "$log_file"
    elif [ -n "$changes" ]; then
        echo "[$time_now] Change detected:" >> "$log_file"
        echo "$changes" >> "$log_file"
        echo "" >> "$log_file"
    else
        echo "[$time_now] No change detected." >> "$log_file"
        echo "" >> "$log_file"
    fi
}

main() {
    scan_network
    parse_scan_results
    detect_changes
    log_changes
    /bin/cp "$current_state" "$previous_state"
}

main