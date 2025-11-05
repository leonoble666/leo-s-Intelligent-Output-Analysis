# leo-s-Intelligent-Output-Analysis
🎯 RAIR: Reconnaissance Analysis and Correlation

The RAIR (Reconnaissance Analysis and Correlation) script is a foundational Bash framework designed to automate the initial data collection and triage phase of a penetration test. It focuses on correlating information from common reconnaissance steps (subdomain enumeration, port scanning, and vulnerability checks) to quickly highlight the most actionable leads for manual investigation.

💡 Purpose

In typical reconnaissance, a pentester gathers a vast amount of data (thousands of subdomains, many open ports, and hundreds of low-priority vulnerabilities). RAIR's core function is to intelligently filter, combine, and correlate this data, presenting a focused report of high-priority assets that have:

An associated High-Interest Open Port (e.g., SSH, RDP, custom web proxy).

A Critical or High-Severity Vulnerability detected by automated scanners.

🛠️ Dependencies

This script is written in Bash and uses several standard command-line tools. The placeholders for active scanning assume these industry-standard tools are installed and accessible in your system's PATH.

Tool

Purpose

Status in Script

curl

Passive subdomain enumeration (via crt.sh).

Active

dig

Real-time DNS lookup for IP address resolution.

Active

grep, awk, sed

Data parsing and correlation logic.

Active

nmap

Active port scanning (Simulated).

Placeholder

nuclei

Vulnerability check (Simulated).

Placeholder

Note: You must replace the "MOCK DATA" sections in rair_analyzer.sh with the actual execution and parsing logic for nmap and nuclei for a fully functional workflow.

🚀 Usage

1. Make the Script Executable

chmod +x rair_analyzer.sh


2. Run the Script

The script will prompt you for the target domain name.

./rair_analyzer.sh


Example Run:

[?] Please enter the target domain (e.g., example.com):
targetcorp.com
[+] Target set to: targetcorp.com
[*] Initializing data collection for targetcorp.com...
... (Data collection steps run)


📋 Understanding the Output

The Correlated High-Value Findings Report is the final output of the analysis phase. It only lists assets where the correlation logic found a high-interest factor.

Indicator

Meaning

--- LEAD #X ---

Marks a unique target that warrants manual attention.

🌐 TARGET ASSET:

The subdomain and its resolved IP address (the target).

💡 Open Ports:

Lists high-interest ports found on that IP (e.g., 22/ssh).

❗ RISK ALERT:

A critical warning, typically flagged when highly sensitive ports like RDP (3389/ms-wbt-server) or SSH (22/ssh) are exposed.

🚨 VULN FINDING:

Indicates a CRITICAL vulnerability was found by the mock Nuclei output.

⚠️ VULN FINDING:

Indicates a HIGH vulnerability was found by the mock Nuclei output.
