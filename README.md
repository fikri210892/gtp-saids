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

========Wait Until Finished==========================================

3. Capture GTP Attack on VM1
- sudo tcpdump -i ens33 port 2152 -w attack_flood.pcap

5. Run attack-1 on VM3
- sudo python3 gtp_attack.py -a 2 -c 1000


========Wait Until Finished==========================================

6. Capture GTP Attack on VM1
- sudo tcpdump -i ens33 port 2152 -w attack_invalid_teid.pcap

7. Run attack-2 on VM3
- sudo python3 gtp_attack.py -a 3

========Wait Until Finished==========================================

8. Capture GTP Attack on VM1
- sudo tcpdump -i ens33 port 2152 -w attack_spoofing.pcap

9. Run attack-3 on VM3
- sudo python3 gtp_attack.py -a 4 -c 1000

========Wait Until Finished==========================================


