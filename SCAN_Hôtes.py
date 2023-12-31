from scapy.all import *

reseaux = input("veuillez entrer le réseaux à analiser : ")
Methode = int(input("Veuillez choisir la métode à utiliser : (Active = ICMP : 1 OU Passive = ARP : 2)       "))
S1 = reseaux.split(".")
print(S1)



BILAN = [f"BILAN DE L'ANALYSE DU RESEAUX : {reseaux}"]


for i in range (0 , 256):
    ip = f"{S1[0]}.{S1[1]}.{S1[2]}.{i}"
    print(ip)


    if Methode == 1 :
        packet = IP(dst=ip)/ICMP()
        reponse = sr1(packet, timeout=2)
    
    if  Methode == 2:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
        reponse = srp1(packet, timeout=2)


    

    if reponse :
        if Methode == 1:
            print(f"{ip} ---------------> existe sur le réseaux : {reseaux}")
            BILAN.append(f"{ip} ---------------> existe sur le réseaux : {reseaux}")
        else:
            print(f"{ip} ---------------> existe sur le réseaux avec comme adresse MAC : {reponse.hwsrc}")
            BILAN.append(f"{ip} ---------------> existe sur le réseaux avec comme adresse MAC : {reponse.hwsrc}")
    else :
        print(f"{ip} n'existe pas")


for k in BILAN:
    print (k)