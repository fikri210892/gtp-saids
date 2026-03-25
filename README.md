
# GTP-AEGIS

Repository for **GTP attack simulation** on a 5G network (Open5GS + UERANSIM) up to capturing PCAP files. Detection/analysis methods are in a separate repo (part 2).

---

## Repository Structure

```
gtp-aegis/
├── config/              # Open5GS & UERANSIM reference configs
│   ├── amf.yaml
│   ├── smf.yaml
│   ├── upf.yaml
│   ├── hss.yaml
│   ├── open5gs-gnb.yaml
│   └── open5gs-ue.yaml
├── scripts/
│   └── gtp_attack.py    # GTP-U attack tool (research only)
├── README.md
├── requirements.txt     # Python deps for VM3 only
└── .gitignore
```

---

## Requirements by VM

The lab uses **3 VMs**. Each has different software requirements:

| VM  | Role           | What you need |
|-----|----------------|---------------|
| **VM1** | 5G core + traffic capture | Open5GS, MongoDB, WebUI, `tcpdump` |
| **VM2** | RAN + UE       | UERANSIM (gNB + UE) only |
| **VM3** | Attacker       | Python 3 + Scapy (this repo’s `requirements.txt`) |

### VM1 — Open5GS (core network + capture)

Follow **[Open5GS Quickstart](https://open5gs.org/open5gs/docs/guide/01-quickstart/)** to install:

- **MongoDB** (subscriber data)
- **Open5GS** packages (AMF, SMF, UPF, HSS, etc.)
- **WebUI** (Node.js required) for subscriber management
- **tcpdump** (usually preinstalled) for capturing GTP traffic on port 2152

Reference configs (AMF, SMF, UPF, HSS) are in the `config/` folder. Copy them to your Open5GS config location and adjust IPs/interfaces (e.g. `ens33`) for your VM.

### VM2 — UERANSIM (gNB + UE)

Install and configure **UERANSIM** only:

- [UERANSIM repository](https://github.com/aligungr/UERANSIM)

Use the reference configs in `config/` (`open5gs-gnb.yaml`, `open5gs-ue.yaml`) and set IPs to match your setup (e.g. VM1 = Open5GS, VM2 = UERANSIM).

### VM3 — Attacker

Only needs Python and the attack script dependencies:

- **Python 3**
- **Scapy** — install with: `pip install -r requirements.txt` (from this repo root)

No Open5GS or UERANSIM on VM3.

---

## Verify setup (VM1 + VM2)

After Open5GS and UERANSIM are running, on **VM2** test UE connectivity:

```bash
ping -I uesimtun0 8.8.8.8 -c100
curl --interface uesimtun0 http://google.com
```

If these succeed, you can proceed with traffic capture and attacks.

---

## Capture Traffic & Run Attacks

All script commands below are run from the **repository root** (e.g. `python3 scripts/gtp_attack.py ...`).

### 1. Normal traffic

**On VM1 (Open5GS):** start capture:

```bash
sudo tcpdump -i ens33 port 2152 -w normal_traffic.pcap
```

**On VM2 (UERANSIM):** generate normal traffic (wait until finished):

```bash
ping -I uesimtun0 8.8.8.8 -c1000
# or
curl --interface uesimtun0 http://google.com
# or
curl --interface uesimtun0 -O http://speedtest.tele2.net/10MB.zip
```

Then stop `tcpdump` on VM1.

---

### 2. Attack 1 — GTP-U flood

**VM1:**

```bash
sudo tcpdump -i ens33 port 2152 -w attack_flood.pcap
```

**VM3 (from repo root):**

```bash
sudo python3 scripts/gtp_attack.py -a 2 -c 1000
```

Wait until the attack finishes, then stop `tcpdump` on VM1.

---

### 3. Attack 2 — Invalid TEID

**VM1:**

```bash
sudo tcpdump -i ens33 port 2152 -w attack_invalid_teid.pcap
```

**VM3:**

```bash
sudo python3 scripts/gtp_attack.py -a 3
```

---

### 4. Attack 3 — Spoofing

**VM1:**

```bash
sudo tcpdump -i ens33 port 2152 -w attack_spoofing.pcap
```

**VM3:**

```bash
sudo python3 scripts/gtp_attack.py -a 4 -c 1000
```

---

## `gtp_attack.py` options

| Option   | Description |
|----------|-------------|
| `-a 1`–`7` | Attack type (7 = run all) |
| `-t <IP>`  | Target IP (default: Open5GS IP) |
| `-c <n>`   | Packet count (for attacks that support it) |

---

## Part 2 (detection/analysis)

For the next step (analysis and detection):  
[https://github.com/fikri210892/gtp-aegis-2](https://github.com/fikri210892/gtp-aegis-2)
=======
Welcome to my github.
On this thread i will share my research that is Signature and Anomaly IDS on General Packet Radio Service Tunelling Protocol.

First you need to install OPEN5GS and UERANSIM. Go to this page to install and configure OPEN5GS https://open5gs.org/open5gs/docs/guide/01-quickstart/

Go to this page to install and configure UERANSIM
https://github.com/aligungr/UERANSIM

After you configure OPEN5GS and UERANSIM, test the uesimtun port using
- ping -I uesimtun0 8.8.8.8 -c100
- curl --interface uesimtun0 http://google.com

If success you can continue, but if still failed you need tou troubleshoot it first. I attach my AMF,SMF,UPF,GNB,UE configurations as a refference.

My simulation using 3VMs.
1. VM1- Open5gs as a core network
2. VM2- Ueransim as a gnodeb and ue
3. VM3- Attacker
   
**Traffic Capture and Run Traffic**

1. Capture GTP Normal traffic on VM1(Open5gs)

- sudo tcpdump -i ens33 port 2152 -w normal_traffic.pcap

2. Run normal traffic on VM2(Ueransim)
- ping -I uesimtun0 8.8.8.8 -c1000 or
- curl --interface uesimtun0 http://google.com or
- curl --interface uesimtun0 -O http://speedtest.tele2.net/10MB.zip



3. Capture GTP Attack on VM1
- sudo tcpdump -i ens33 port 2152 -w attack_flood.pcap

5. Run attack-1 on VM3
- sudo python3 gtp_attack.py -a 2 -c 1000


6. Capture GTP Attack on VM1
- sudo tcpdump -i ens33 port 2152 -w attack_invalid_teid.pcap

7. Run attack-2 on VM3
- sudo python3 gtp_attack.py -a 3


8. Capture GTP Attack on VM1
- sudo tcpdump -i ens33 port 2152 -w attack_spoofing.pcap

9. Run attack-3 on VM3
- sudo python3 gtp_attack.py -a 4 -c 1000


If you have finished, continue to part 2
https://github.com/fikri210892/gtp-aegis-2
>>>>>>> fb954d05430e7f9d1b82c44e7f6a44dcf814062e
