#!/bin/bash

# =========================================================
# RECONNAISSANCE ANALYSIS AND CORRELATION (RAIR)
# =========================================================
# This script is now an active framework for collecting,
# analyzing, and correlating live reconnaissance data.
#
# Focus: Linking subdomains to open high-interest ports and
# high-severity vulnerabilities.
# =========================================================

# --- 1. CONFIGURATION AND COLORS ---
TARGET_DOMAIN="" # Will be set by user input
OUTPUT_DIR="rair_output"
REPORT_FILE="${OUTPUT_DIR}/correlated_findings.txt"

RED='\033[0;31m'    # High Severity / Critical
GREEN='\033[0;32m'  # Success / Info
YELLOW='\033[0;33m' # Warning / Medium Severity
BLUE='\033[0;34m'   # Report Header
NC='\033[0m'        # No Color

# Ports considered high interest for initial access leads
HIGH_INTEREST_PORTS="21 22 23 80 443 3389 8080"


# --- 2. HELPER FUNCTIONS ---

# Function to get the target domain from the user
get_target_domain() {
    echo -e "${GREEN}[?] Please enter the target domain (e.g., example.com):${NC}"
    read -r input_domain

    if [ -z "$input_domain" ]; then
        echo -e "${RED}Error:${NC} No domain name provided. Exiting."
        exit 1
    fi
    TARGET_DOMAIN="$input_domain"
    echo -e "${GREEN}[+] Target set to: ${BLUE}${TARGET_DOMAIN}${NC}"
}

# Function to look up the IP for a given domain using 'dig'
get_ip_from_domain() {
    local domain=$1
    # Use dig to get the A record, filter for the IP, and select the first one
    # If dig is not available or resolution fails, it returns an empty string
    dig +short A "$domain" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | head -n 1
}


# Function to collect actual data using reconnaissance tools
collect_live_data() {
    echo -e "${GREEN}[*] Initializing data collection for ${TARGET_DOMAIN}...${NC}"
    rm -rf "${OUTPUT_DIR}" 2>/dev/null # Clean up previous run silently
    mkdir -p "${OUTPUT_DIR}"

    # --- Step 1: Subdomain Enumeration (Passive via crt.sh) ---
    echo -e "${YELLOW}[-] Collecting subdomains via Certificate Transparency logs...${NC}"
    curl -s "https://crt.sh/?q=%.${TARGET_DOMAIN}" | \
    grep -oE '([a-zA-Z0-9-]+\.){1,10}'"${TARGET_DOMAIN}" | \
    sort -u > "${OUTPUT_DIR}/subdomains.txt"

    SUBDOMAIN_COUNT=$(wc -l < "${OUTPUT_DIR}/subdomains.txt")
    echo -e "${GREEN}[+] Found ${SUBDOMAIN_COUNT} unique subdomains.${NC}"

    # --- Step 2: Placeholder for Nmap Scan (Active) ---
    # NOTE: Running Nmap requires appropriate permissions and time.
    # In a real script, the Nmap command would be here, piping relevant output.
    # Example: nmap -p ${HIGH_INTEREST_PORTS} -iL ${OUTPUT_DIR}/ip_list.txt -oG ${OUTPUT_DIR}/nmap_grepable.txt
    
    echo -e "${YELLOW}[-] Generating mock Nmap data for demonstration...${NC}"
    # MOCK NMAP DATA: You would replace this block with your actual Nmap parsing logic.
    cat > "${OUTPUT_DIR}/nmap_open_ports.txt" << EOF
192.0.2.1:80:http
192.0.2.2:443:https
192.0.2.2:8080:http-proxy
192.0.2.3:22:ssh
192.0.2.3:80:http
192.0.2.4:3389:ms-wbt-server
EOF
    # END MOCK NMAP DATA

    # --- Step 3: Placeholder for Nuclei Scan (Vulnerability Check) ---
    # NOTE: Running Nuclei requires the tool and templates to be installed.
    # In a real script, the Nuclei command would be here, piping high-severity output.
    # Example: nuclei -l ${OUTPUT_DIR}/subdomains.txt -severity high,critical -o ${OUTPUT_DIR}/nuclei_high_severity.txt

    echo -e "${YELLOW}[-] Generating mock Nuclei data for demonstration...${NC}"
    # MOCK NUCLEI DATA: You would replace this block with your actual Nuclei parsing logic.
    cat > "${OUTPUT_DIR}/nuclei_high_severity.txt" << EOF
http://dev.${TARGET_DOMAIN}:MEDIUM:default-login-page
https://internal-git.${TARGET_DOMAIN}:CRITICAL:git-config-exposure
http://legacy-server.${TARGET_DOMAIN}:HIGH:old-apache-default-page
EOF
    # END MOCK NUCLEI DATA

    echo -e "${GREEN}[+] Data collection phase complete.${NC}"
}

# --- 3. CORRELATION LOGIC ---

analyze_and_correlate() {
    echo -e "${BLUE}====================================================${NC}"
    echo -e "${BLUE}      🎯 CORRELATED HIGH-VALUE FINDINGS REPORT${NC}"
    echo -e "${BLUE}====================================================${NC}"

    # Initialize a counter for found leads
    local lead_count=0

    # Read each subdomain from the generated list
    while IFS= read -r subdomain || [[ -n "$subdomain" ]]; do
        if [ -z "$subdomain" ]; then continue; fi

        local ip_address
        # Use the real DNS lookup function
        ip_address=$(get_ip_from_domain "$subdomain")

        if [ -z "$ip_address" ]; then
            # If get_ip_from_domain failed, try a fallback (e.g., CNAME/TXT records) or skip
            # We skip for now to keep the script focused.
            echo -e "[-] Could not resolve IP for ${subdomain}. Skipping."
            continue
        fi

        # ------------------------------------------------------------------
        # Correlation Step 1: Check for High-Interest Open Ports
        # ------------------------------------------------------------------
        local open_ports_found=""

        # Iterate through the pre-defined high-interest ports
        for port in ${HIGH_INTEREST_PORTS}; do
            # Use grep to check if the current IP and Port are found in the Nmap data
            if grep -q "${ip_address}:${port}:" "${OUTPUT_DIR}/nmap_open_ports.txt" 2>/dev/null; then
                # Extract the full entry (IP:Port:Service) and append it
                local service_info
                service_info=$(grep "${ip_address}:${port}:" "${OUTPUT_DIR}/nmap_open_ports.txt" | awk -F':' '{print $3}' | head -n 1)
                open_ports_found="${open_ports_found}${port}/${service_info}, "
            fi
        done

        # Remove trailing comma and space
        open_ports_found=$(echo "$open_ports_found" | sed 's/, $//')


        # ------------------------------------------------------------------
        # Correlation Step 2: Check for High-Severity Vulnerabilities (Nuclei)
        # ------------------------------------------------------------------
        local nuclei_finding_info=""

        # Use grep to find if the subdomain is mentioned in the nuclei findings
        nuclei_raw_findings=$(grep "${subdomain}" "${OUTPUT_DIR}/nuclei_high_severity.txt")

        if [ ! -z "$nuclei_raw_findings" ]; then
            # If multiple findings exist, we only take the first one for simplicity in this report format.
            nuclei_finding_info=$(echo "$nuclei_raw_findings" | head -n 1 | awk -F':' '{print $2 " (" $3 ")"}')
        fi


        # ------------------------------------------------------------------
        # Correlation Step 3: Reporting - Filter for actionable leads
        # ------------------------------------------------------------------

        # If *either* open ports *or* high-severity findings exist, print the lead.
        if [ ! -z "$open_ports_found" ] || [ ! -z "$nuclei_finding_info" ]; then
            lead_count=$((lead_count + 1))
            
            # Print the header for the specific lead
            echo -e "${BLUE}--- LEAD #${lead_count} ---------------------------------------------------${NC}"
            echo -e "🌐 ${YELLOW}TARGET ASSET:${NC} ${subdomain} (${ip_address})"
            
            # Print Open Port Findings (Highlighting High-Interest Services)
            if [ ! -z "$open_ports_found" ]; then
                echo -e "  💡 ${GREEN}Open Ports:${NC} ${open_ports_found}"
                # Additional alert for especially risky services
                if [[ "$open_ports_found" =~ "ssh" || "$open_ports_found" =~ "ms-wbt-server" ]]; then
                    echo -e "  ❗ ${RED}RISK ALERT:${NC} RDP/SSH exposed. Immediate manual login attempt recommended."
                fi
            fi

            # Print Vulnerability Findings
            if [ ! -z "$nuclei_finding_info" ]; then
                # Color code the severity based on the first word (CRITICAL or HIGH)
                if [[ "$nuclei_finding_info" =~ "CRITICAL" ]]; then
                    echo -e "  🚨 ${RED}VULN FINDING:${NC} ${nuclei_finding_info}"
                elif [[ "$nuclei_finding_info" =~ "HIGH" ]]; then
                    echo -e "  ⚠️ ${RED}VULN FINDING:${NC} ${nuclei_finding_info}"
                else
                    echo -e "  🔎 ${YELLOW}VULN FINDING:${NC} ${nuclei_finding_info}"
                fi
            fi
        fi

    done < "${OUTPUT_DIR}/subdomains.txt"

    echo -e "${BLUE}====================================================${NC}"
    echo -e "${GREEN}[+] Analysis Complete. Found ${lead_count} actionable leads.${NC}"
}

# --- 4. EXECUTION ---

# Get user input
get_target_domain

# Collect data (replaces create_mock_data)
collect_live_data

# Run the core analysis
analyze_and_correlate

# Cleanup output directory (optional, can be commented out)
# rm -rf "${OUTPUT_DIR}"
