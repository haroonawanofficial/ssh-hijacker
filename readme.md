# SSH Hijacker — Interceptor

A silent SSH hijacker that operates and outplays encryption. It intercepts and logs SSH handshakes, relays traffic silently, and supports stealth techniques like MAC spoofing and invisible network presence.


## 🚀 Features

- SSH interceptor with full banner relay
- Works with encryption phase 
- `--invisible` mode: hides attacker in network using `iptables`
- `--macspoof`: randomizes attacker MAC address
- Auto restores system settings on exit
- Wireshark and other tcp dumper can not see attacker ip using ivisible mode
- attacker ip is not traceable even with forensic tool using invisible mode


## Legal Disclaimer

> This tool is intended for **authorized security research and red-team engagements only**. Unauthorized use is illegal and unethical.

---

## Requirements

- Linux (Debian/Ubuntu)
- Python 3.6+
- Root privileges

---

## Installation

```bash
git clone https://github.com/haroonawanofficial/ssh-hijacker.git
cd ssh-hijacker
sudo python3 ssh_hijacker.py --port 22
```

## How to use

```bash
sudo python3 ssh_hijacker.py --invisible --macspoof eth0
```

> Benefits on same network:

1. Redirect all SSH traffic to you
2. Spoof your MAC
3. Hide you from trace in SSH logs
4. Hide you from any forensic tool and wireshark
