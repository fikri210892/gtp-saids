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
   
**Traffic Capture and Analysis**

1. Capture GTP-U traffic for analysis and IDS training on VM1(Open5gs)

sudo tcpdump -i ens33 port 2152 -w normal_traffic.pcap

Run normal traffic on VM2(Ueransim)
- ping -I uesimtun0 8.8.8.8 -c1000
- curl --interface uesimtun0 http://google.com
- curl --interface uesimtun0 -O http://speedtest.tele2.net/10MB.zip

2. Capture Attack Traffic 




