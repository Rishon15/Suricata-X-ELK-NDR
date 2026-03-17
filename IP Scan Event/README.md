# TA0007 Discovery

Tactic used by an adversary to find out devices in the network that may have vulnerabilities in them or misconfigurations. This tactic is usually a pre-requisite to Lateral Movement or Privilege escalationa that compromises other devices or users within the network.

## T1046 Network Service Discovery

Uses techniques like port scanning to listen on remote hosts for services. Done via automatic port scanning tools that generate rapid, high-volume TCP connection requests (SYN packets) across multiple IP addresses.

### 1. Scenario

This module simulates an outbound scan from a compromised internal host, done to test the detections and refine/tune existing rules to get high-fidelity alerts.

### 2. Problem

On testing out-of-box rules like the Emerging Threats rules, its observed to trigger only when port 22 was probed and not when other ports were probed, proving to have many blindspots. Furthermore, previously devised rules were being triggered due to benign telemetry (Eg - Elastic & Mozilla) causing many flase positives and cluttering the dashboard.

### 3. Solution

1. Engineered a custom rule that triggers based on the volume of outbound TCP packets with the synchronised (SYN) flag set.
2. Engineered a PCRE (Regex) whitelist rule to explicitly pass known benign background telemetry, ensuring SIEM dashboard remains focused on actionable threats.

### 4. Custom Ruleset

```Plaintext
# Silnecer Rule (Broad Whitelist for background browser noise)
pass dns $HOME_NET any -> any any (msg:"WHITELIST - Benign Browser/Telemetry Noise"; dns.query; pcre:"/(elastic\.co|mozilla\.(com|net)|fastly-edge\.com|example\.org|hbr\.org)/i"; sid:1000090; rev:1;)

# Rule to alert on high volume outbound traffic
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"RECON - Outbound Port Scan Detected (High Volume SYN)"; flags:S; threshold: type both, track by_src, count 10, seconds 5; classtype:attempted-recon; priority:3; sid:1000080; rev:1;)
```

### 5. Result

![IP scan event result](../Pictures/IP%20Scan%20Event.png)

The Suricata engine successfully detected the ignature of the port scan immediately upon execution. Kibana confirmed the custom RECON rule tracked the attack consistently across multiple IPs and non-standard ports (e.g., 139, 5900, 3389) that bypassed static signatures. Simultaneously, the WHITELIST rule successfully suppressed all benign telemetry noise, resulting in a pristine incident timeline.

