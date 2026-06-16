# ARP Spoofing & MITM Detection Lab

**Tools:** Kali Linux · arpspoof · Wireshark  
**Techniques:** ARP Cache Poisoning · MITM Attack · Layer 2 Traffic Analysis  
**Environment:** VMware Fusion Home Lab (MacBook Air)  
**Difficulty:** Intermediate

-----

## Objective

Simulate a Man-in-the-Middle (MITM) attack using ARP cache poisoning, capture the malicious traffic in Wireshark, and identify the indicators of compromise (IOCs) a SOC analyst would use to detect this attack in a real network environment.

-----

## Lab Environment

|Role    |Host                 |IP Address    |MAC Address      |
|--------|---------------------|--------------|-----------------|
|Attacker|Kali Linux           |172.16.148.132|00:0c:29:e7:7f:95|
|Victim  |Metasploitable2      |172.16.148.133|00:50:56:f3:92:0d|
|Gateway |VMware Virtual Router|172.16.148.2  |—                |

**Network:** 172.16.148.0/24 · Interface: eth0

-----

## Background

### What is ARP Spoofing?

ARP (Address Resolution Protocol) operates at Layer 2 of the OSI model and maps IP addresses to MAC addresses on a local network. ARP has no built-in authentication — any host can send an unsolicited ARP reply claiming any IP address belongs to its MAC.

An attacker exploits this by sending **gratuitous ARP replies** to both the victim and the gateway, telling each that the attacker’s MAC address corresponds to the other’s IP. This poisons both ARP caches, routing all traffic through the attacker — a classic **Man-in-the-Middle (MITM)** position.

### Why This Matters for SOC Analysts

ARP spoofing is a foundational MITM technique used to:

- Intercept plaintext credentials (FTP, Telnet, HTTP)
- Perform SSL stripping attacks
- Stage further attacks like DNS poisoning
- Conduct internal network reconnaissance

Detection at the network level relies on recognizing the traffic patterns this lab demonstrates.

-----

## Attack Methodology

### Step 1 — Enable IP Forwarding

To act as a true MITM, the attacker must forward traffic between the victim and gateway rather than dropping it (which would cause a denial of service and alert the victim).

```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

This tells the Kali kernel to forward packets destined for other hosts rather than discarding them.

-----

### Step 2 — Start Wireshark Capture

Launched Wireshark on interface **eth0** with the `arp` display filter applied to isolate ARP traffic.

```
Filter: arp
```

-----

### Step 3 — Launch ARP Poisoning (Two-Way)

Two simultaneous `arpspoof` instances are required to poison both directions of traffic:

**Terminal 1 — Poison the victim (tell Metasploitable2 that Kali is the gateway):**

```bash
sudo arpspoof -i eth0 -t 172.16.148.133 172.16.148.2
```

**Terminal 2 — Poison the gateway (tell the router that Kali is the victim):**

```bash
sudo arpspoof -i eth0 -t 172.16.148.2 172.16.148.133
```

Both commands flood the targets with unsolicited ARP replies at approximately 1-second intervals, continuously overwriting the legitimate ARP cache entries.

-----

## Wireshark Analysis

### IOC #1 — Unsolicited ARP Replies (Opcode 2)

Normal ARP follows a request/reply pattern: a host broadcasts a request, the target responds. In an ARP spoofing attack, the attacker sends **unsolicited replies (Opcode 2)** with no preceding request — a major red flag.

**Packet dissection (Frame 194):**

```
Address Resolution Protocol (reply)
  Hardware type: Ethernet (1)
  Protocol type: IPv4 (0x0800)
  Opcode: reply (2)                          ← Unsolicited reply, no request preceded this
  Sender MAC address: 00:0c:29:e7:7f:95      ← Kali's MAC (the attacker)
  Sender IP address:  172.16.148.2           ← Gateway's IP (Kali is LYING)
  Target MAC address: 00:00:00:00:00:00
  Target IP address:  172.16.148.133         ← Metasploitable2 (the victim)
```

The attacker’s MAC (`00:0c:29:e7:7f:95`) is being advertised as the owner of the gateway IP (`172.16.148.2`). The victim will update its ARP cache and send all gateway-bound traffic to Kali instead.

-----

### IOC #2 — High-Frequency ARP Traffic

Normal ARP is infrequent — a host only sends requests when it needs to resolve a new IP. During this attack, **335+ ARP packets** were captured in under 10 minutes, all sourced from the same MAC address. This volume of ARP replies from a single host is anomalous and would trigger alerts in a SIEM with ARP rate-threshold rules.

**Traffic pattern observed:**

- All packets sourced from `VMware_e7:7f:95` (Kali)
- Alternating destinations: broadcast and `VMware_f3:92:0d` (gateway)
- Interval: approximately every 2 seconds per direction

-----

### IOC #3 — Duplicate IP Address Detection

Wireshark’s built-in ARP analysis flagged the attack automatically:

```
[Duplicate IP address detected for 172.16.148.2 (00:0c:29:e7:7f:95)]
  [Frame showing earlier use of IP address: 193]
  [Seconds since earlier frame seen: 1]
```

This alert fires when Wireshark sees the same IP address claimed by two different MAC addresses. The gateway IP `172.16.148.2` was legitimately associated with the router’s MAC, then suddenly claimed by Kali’s MAC — 1 second apart. This is the clearest single indicator of ARP poisoning.

-----

## Summary of Indicators of Compromise (IOCs)

|IOC                                  |Description                                 |Normal Behavior                          |
|-------------------------------------|--------------------------------------------|-----------------------------------------|
|Unsolicited ARP replies (Opcode 2)   |ARP replies sent without a preceding request|Replies only follow requests             |
|Duplicate IP detected                |Same IP mapped to two different MACs        |One IP = one MAC on a LAN                |
|High ARP volume from single host     |300+ ARP packets from one MAC in minutes    |ARP traffic is sparse and intermittent   |
|Gateway IP claimed by non-gateway MAC|Attacker’s MAC advertising the router’s IP  |Only the router advertises the gateway IP|

-----

## Detection Rule (Snort 3.x)

The following Snort rule detects unsolicited ARP replies — the core signature of this attack:

```
alert arp any any -> any any (
  msg:"ARP Spoofing - Unsolicited ARP Reply Detected";
  arp.opcode:2;
  sid:9000001;
  rev:1;
)
```

**Note:** For production environments, combine this with a rate threshold (e.g., more than 10 ARP replies from the same source in 5 seconds) and cross-reference against a known MAC-to-IP mapping table to reduce false positives.

-----

## Defensive Countermeasures

|Control                       |Description                                                                                             |
|------------------------------|--------------------------------------------------------------------------------------------------------|
|Dynamic ARP Inspection (DAI)  |Managed switches can validate ARP packets against a DHCP snooping binding table and drop spoofed replies|
|Static ARP entries            |Manually configure critical hosts (gateway, DNS) with permanent ARP entries that cannot be overwritten  |
|Network segmentation          |VLANs limit the blast radius — ARP spoofing is confined to the local broadcast domain                   |
|ARP monitoring / SIEM alerting|Tools like XArp, Snort, or Zeek can alert on ARP anomalies in real time                                 |
|Encrypted protocols           |Even with a successful MITM position, TLS/SSH prevents credential interception                          |

-----

## Key Takeaways

- ARP spoofing is a **Layer 2 attack** that requires no credentials — just network access
- The attack is **silent to the victim** — no errors or alerts are generated on the compromised host
- Wireshark’s duplicate IP detection provides an immediate visual indicator during live captures
- SOC analysts should watch for **high-volume ARP replies from a single MAC** and **IP-to-MAC conflicts** as primary detection signals
- IP forwarding must be enabled for a true MITM; without it the attack causes a denial of service instead

-----

## Tools Used

|Tool                   |Purpose                                            |
|-----------------------|---------------------------------------------------|
|arpspoof (dsniff suite)|Generate ARP poisoning traffic                     |
|Wireshark 4.6.4        |Capture and analyze ARP packets                    |
|ip route / ip addr     |Network reconnaissance and interface identification|

-----

*Lab conducted in an isolated VMware Fusion home lab environment. All targets are intentionally vulnerable VMs. No production systems were affected.*
