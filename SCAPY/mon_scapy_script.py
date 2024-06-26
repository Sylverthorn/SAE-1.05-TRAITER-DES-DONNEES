from scapy.all import IP, ICMP, sr1, srp1, Ether, ARP, send, logging
import argparse
import ipaddress



logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

RESULTAT = ["RESULTAT DU SCAN", "----------------------------------------"]
ROUGE = '\033[91m'
VERT = '\033[92m'
RESET = '\033[0m'
FICHIER = '\033[93m'

def active(ip):
    packet = IP(dst=str(ip))/ICMP()
    réponse = sr1(packet, timeout=2)

    
    if réponse :
        print(f"{VERT}L'IP : {ip} existe !!{RESET}")
        RESULTAT.append(ip)
    else :
        print(f"{ROUGE}L'IP : {ip} n'existe pas ...{RESET}")



def passive(ip):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=str(ip))
    réponse = srp1(packet, timeout = 2)

    if réponse:
        RESULTAT.append(f"{ip}                  {réponse.hwsrc}")
        print(f"{VERT}L'IP : {ip} existe avec comme adresse MAC : {réponse.hwsrc}!!{RESET}")
    else :
        réponse = srp1(packet, timeout = 2)
        if réponse:
            RESULTAT.append(f"{ip}              {réponse.hwsrc}")
            print(f"{VERT}L'IP : {ip} existe avec comme adresse MAC : {réponse.hwsrc}!!{RESET}")
            
        else :
            print(f"L'IP : {ip} existe !!")
        



def découverte_total(reseau):
    if "/" not in reseau:
            reseau = input("{ROUGE}ERREUR ! mauvais format, essayé sous cette forme : xx.xx.xx.xx/xx : ")
    else :  
                for ip_addr in ipaddress.IPv4Network(reseau):
                    packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=str(ip_addr))
                    rép = srp1(packet, timeout = 2, verbose=0)
                    if rép :
                        MAC = rép.hwsrc

                        
                    packet = IP(dst=str(ip_addr))/ICMP()
                    réponse = sr1(packet, timeout=2, verbose=0)
        
                    if réponse :    
                        
                        print(f"{VERT}L'IP : {ip_addr} existe !!{RESET}")
                        RESULTAT.append(f"{ip_addr}                  {MAC}")
                    else :
                        print(f"{ROUGE}L'IP : {ip_addr} n'existe pas ...{RESET}")



def resultat(list, fich):
    if len(list) > 2 :
        print (f"LE RESULTAT EST DISPONIBLE DANS LE FICHIER : {FICHIER}{fich}.txt{RESET}")
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
