from scapy.all import IP, ICMP, sr1, srp1, Ether, ARP, send
import argparse
import ipaddress



def active(ip):
    packet = IP(dst=str(ip))/ICMP()
    réponse = sr1(packet, timeout=2)

    
    if réponse :
        print(f"L'IP : {ip} existe !!")
        RESULTAT.append(ip)
    else :
        print(f"L'IP : {ip} n'existe pas ...")



def passive(ip):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=str(ip))
    réponse = srp1(packet, timeout = 2)

    if réponse:
        RESULTAT.append(f"{ip}                  {réponse.hwsrc}")
        print(f"L'IP : {ip} existe avec comme adresse MAC : {réponse.hwsrc}!!")
    else :
        réponse = srp1(packet, timeout = 2)
        if réponse:
            RESULTAT.append(f"{ip}              {réponse.hwsrc}")
            print(f"L'IP : {ip} existe avec comme adresse MAC : {réponse.hwsrc}!!")
            
        else :
            print(f"L'IP : {ip} existe !!")
        



def découverte_total(reseau):
    if "/" not in reseau:
        reseau = input("ERREUR ! mauvais format, essayé sous cette forme : xx.xx.xx.xx/xx : ")
    else : 
        for ip_addr in ipaddress.IPv4Network(reseau):
            packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=str(ip_addr))
            rép = srp1(packet, timeout = 2, verbose=0)
            if rép :
                MAC = rép.hwsrc
            packet = IP(dst=str(ip_addr))/ICMP()
            réponse = sr1(packet, timeout=2, verbose=0)
  
            if réponse :    
                
                print(f"L'IP : {ip_addr} existe !!")
                RESULTAT.append(f"{ip_addr}                  {MAC}")
            else :
                print(f"L'IP : {ip_addr} n'existe pas ...")




def resultat(list, fich):
    if len(list) > 2 :
        print (f"LE RESULTAT EST DISPONIBLE DANS LE FICHIER : {fich}.txt")
        with open(f"{fich}.txt", 'w') as fichier:
            for i in list:
                fichier.write(f"{i}\n")   
    else :
        print("AUCUN RESULTAT")



parser = argparse.ArgumentParser(description="--------SCAN DES HOTES D'UN RESEAU--------")
parser.add_argument("-p", metavar="< xx.xx.xx.xx >", help="L'option -p permet de déclencher une découverte passive, avec comme argument l'adresse IP de l'hôte cible.")
parser.add_argument("-a", metavar="< xx.xx.xx.xx >", help="L'option -a déclenche la découverte active avec l'adresse IP d'un hôte qui sera donnée en argument.")
parser.add_argument("-t", metavar="< xx.xx.xx.xx/xx>", help="L'option -t permet de tester la présence de l'ensemble des hôtes d'un réseau avec ICMP et dont l'adresse réseau est donnée en argument.")
parser.add_argument("-x", metavar="nom du fichier")
args = parser.parse_args()

RESULTAT = ["RESULTAT DU SCAN", "----------------------------------------"]

if args.p:
    passive(args.p)
elif args.a:
    active(args.a)
elif args.t:
    découverte_total(args.t)
else:
    print("argument non pris en charge : -h ou --help pour de l'aide")

if args.x:
    resultat(RESULTAT, args.x)   
