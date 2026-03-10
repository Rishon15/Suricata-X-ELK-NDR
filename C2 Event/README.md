# TA0011 Command & Control (C2)

Tactic used by adversaries to communicate with compromised systems to control them. Command & Control traffic is often disguised as normal, expected network traffic to avoid detection.

## T1568: Dynamic Resolution

Adversaries dynamically establish connections to C2 infrastructures to evade signature based detections and static blacklists, thus hiding malicious activities within standard DNS/HTTP traffic.

### 1. Scenario

This module simulates dns traffic to adversary's C2 architecture, done to evaluate Suricata + ELK pipeline's ability to detect dynamic adversary infrastructure and automated callbacks.

### 2. Problem

![Before rules image](../Pictures/Before%20Rule-C2.png)

Relying on static threat intelligence blacklist (like Emerging Threats Community Rules) is insufficient for modern C2 frameworks. While ET rules catch known malicious domains, evasive techniques like newly registered Dynamic DNS or throwaway Top Level Domains (TLDs), often bypass signature based engine.

### 3. Solution 

Transitioned from flat signature matching to a layered Detection Engineering strategy to catch zero-day infrastructure and behavioral anomalies:

1. **Action-Order Whitelisting**: Silenced known-benign noise before it hit the detection engine to allow for accurate thresholding and eliminate false positives.

2. **Behavioral Thresholds**: Flagged automated, rhythmic query volume (beaconing) to catch unknown domains based on machine behavior rather than domain reputation.

3. **PCRE Heuristics**: Authored Regular Expressions (Regex) to catch entire categories of suspicious infrastructure (Free DDNS Tunnels, heavily abused TLDs) rather than playing whack-a-mole with specific, ever-changing domain names.

### 4. Custom Ruleset

```text
# 1. THE SILENCER (Whitelist benign traffic )
pass dns $HOME_NET any -> any any (msg:"WHITELIST - High Volume Benign Domains"; dns.query; pcre:"/(google\.com|youtube\.com|microsoft\.com)/i"; sid:1000060; rev:1;)

# 2. THE BEHAVIORAL THRESHOLD (Priority 4 - May suggest high number of DNS resolution)
alert dns $HOME_NET any -> any any (msg:"HUNTING LEAD - High Volume DNS Queries (Possible Beaconing)"; threshold: type threshold, track by_src, count 5, seconds 10; classtype:misc-activity; priority:4; sid:1000045; rev:1;)

# 3. THE CONTEXTUAL POLICY (Priority 3 - To cath multiple domains commonly known for C2)
alert dns $HOME_NET any -> any any (msg:"POLICY VIOLATION - Dual-Use Tunneling/DDNS Domain (playit/duckdns/ngrok)"; dns.query; pcre:"/(duckdns\.org|playit\.plus|ngrok\.io)/i"; classtype:policy-violation; priority:3; sid:1000040; rev:1;)

# 4. THE HEURISTIC (Priority 2 - Catching highly abused Top-Level Domains/DGA)
alert dns $HOME_NET any -> any any (msg:"HEURISTIC - Suspicious/Rare TLD Queried (.cn / .pro / .xyz / .top / .ru)"; dns.query; pcre:"/\.(cn|pro|xyz|top|ru)$/i"; classtype:bad-unknown; priority:2; sid:1000050; rev:1;)
```

### 5. Result

![After rule image](../Pictures/After%20Rule-C2.png)

The pipeline successfully logged the simulated C2 traffic. The Kibana dashboard captured both the custom threshold/heuristic alerts and the ET community signatures. The whitelist rules successfully dropped the designated benign domains, preventing false positives on the threshold alerts.

#### Engineering Trade-offs

Community signatures (ET rules) are highly optimized for performance using specific byte sizes and fast pattern matching to minimize false positives, but they are rigid and can be evaded if the adversary alters the algorithm. Conversely, custom regex (pcre) rules require more processing overhead but can detect variations in malicious infrastructure that static intelligence feeds miss.
