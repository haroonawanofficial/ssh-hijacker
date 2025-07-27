# SSH Hijacker 

Silent SSH hijacker. It intercepts and logs SSH handshakes, silently relays traffic, and supports advanced stealth techniques such as MAC spoofing and invisible network presence.

---

## Features

- Full SSH interceptor with banner 
- `--invisible` mode: hides attacker IP from network logs  
- `--macspoof`: randomizes attacker MAC address  
- Automatically restores all system settings on exit  
- Invisible to Wireshark and other packet analyzers using `--invisible`  
- Attacker IP is untraceable even with forensic tools  
- Does not break encryption — it outplays it  
- Do **not** use this unless you fully understand what you're doing  

---

## Legal Disclaimer

> This tool is intended strictly for **authorized security research and red-team engagements**.  
> Unauthorized use is illegal and unethical.

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

Benefits on same network:
1. Redirect all SSH traffic to you
2. Spoof your MAC
3. Hide you from trace in SSH logs
4. Hide you from any forensic tool and wireshark
