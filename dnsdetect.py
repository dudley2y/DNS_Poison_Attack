from scapy.all import sniff, ls, IP, DNS, DNSRR, conf, rdpcap
from datetime import datetime
import sys


def defend(pkt): 

    ip = pkt.getlayer(IP)
    dns = pkt.getlayer(DNS)
    dnsrr = pkt.getlayer(DNSRR)

    if ip and dns and dns.qr: 

        key = (ip.src, ip.dst, dns.id)

        if key in defender: 

            if defender[key] == (str(dnsrr.rdata) if dnsrr else "None"): return 

            # spoofed! 

            print("Spoof!")

            with open("attack_log.txt", "a") as logFile: 

                log = "-" + datetime.now().strftime("%b %d %Y %H:%M:%S") + "\n"
                
                log += "-TXID " + str(dns.id) + " Request " + str(dns.qd.qname, "utf-8") + "\n" 

                log += "Answer 1: " + str(defender[key]) + "\n"

                log += "Answer 2: " + (str(dnsrr.rdata) if dnsrr else "None") + "\n\n" 

                logFile.write(log)

        else: 
            defender[key] = str(dnsrr.rdata) if dnsrr else "None"
            # no spoof 

if __name__ == "__main__": 

    defender = {} 

    interface =  sys.argv[sys.argv.index("-i") + 1] if "-i" in sys.argv else conf.iface
    hostname       =  None 
    
    if "-r" in sys.argv: 

        pcap_flow = rdpcap(sys.argv[sys.argv.index("-r") + 1])
        filtered = (pkt for pkt in pcap_flow if pkt.getlayer(DNS))

        for pkt in filtered: 
            defend(pkt)
    else: 
        print("Protector running....")
        print("Listening on " + str(interface))

        dnsfilter = "port 53"
        sniff(iface =interface, filter = dnsfilter, prn = lambda x: defend(x))