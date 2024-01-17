from scapy.all import IP, ICMP, sr1, srp1, Ether, ARP, send, logging, sniff
import argparse
import ipaddress
import sys



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
        print(f"\n{VERT}L'IP : {ip} existe !!{RESET}")
        RESULTAT.append(ip)
    else :
        print(f"\n{ROUGE}L'IP : {ip} n'existe pas ...{RESET}")


def passive(ip):
    def verification_ARP(packet):
         if packet.haslayer(ARP):
            if packet.op == 1:
                 print(f"{VERT}L'Hôte {packet.psrc} existe avec comme adresse MAC : {packet.hwsrc}{RESET}")
                 sys.exit()
            elif packet.op == 2:
                 print(f"{VERT}L'Hôte {packet.psrc} existe avec comme adresse MAC : {packet.hwsrc}{RESET}")
                 sys.exit()
            else:
                 print(f"{ROUGE} L'hote recherché n'existe pas {RESET}")
                 sys.exit()
    
    
    sniff(prn=verification_ARP, filter= f"arp and src host {ip}")
    

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
                        
                        print(f"{VERT}L'IP : {ip_addr} existe !!        avec l'adresse MAC {MAC}{RESET}")
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



print(f"""{ROUGE}

 _    _  ____   _____ _______         _____  _____          _   _   
| |  | |/ __ \ / ____|__   __|       / ____|/ ____|   /\   | \ | | 
| |__| | |  | | (___    | |         | (___ | |       /  \  |  \| |  
|  __  | |  | |\___ \   | |          \___ \| |      / /\ \ | . ` |  
| |  | | |__| |____) |  | |          ____) | |____ / ____ \| |\  |  
|_|  |_|\____/|_____/   |_|         |_____/ \_____/_/    \_\_| \_| 

 ____             __     __         _                           _       _       __                           _ 
|  _ \            \ \   / /        (_)                         | |     | |     /_/                          | |
| |_) |_   _       \ \_/ /_ _ _ __  _ ___        __ _ _ __   __| |     | |     ___  ___  _ __   __ _ _ __ __| |
|  _ <| | | |       \   / _` | '_ \| / __|      / _` | '_ \ / _` |     | |    / _ \/ _ \| '_ \ / _` | '__/ _` |
| |_) | |_| |        | | (_| | | | | \__ \     | (_| | | | | (_| |     | |___|  __/ (_) | | | | (_| | | | (_| |
|____/ \__, |        |_|\__,_|_| |_|_|___/      \__,_|_| |_|\__,_|     |______\___|\___/|_| |_|\__,_|_|  \__,_|
        __/ |                                                                                                  
        |___/                                                                                                   
{RESET}""")


parser = argparse.ArgumentParser(description="--------SCAN DES HOTES D'UN RESEAU--------")
parser.add_argument("-p", metavar="< xx.xx.xx.xx >", help="L'option -p permet de déclencher une découverte passive, avec comme argument l'adresse IP de l'hôte cible.")
parser.add_argument("-a", metavar="< xx.xx.xx.xx >", help="L'option -a déclenche la découverte active avec l'adresse IP d'un hôte qui sera donnée en argument.")
parser.add_argument("-t", metavar="< xx.xx.xx.xx/xx>", help="L'option -t permet de tester la présence de l'ensemble des hôtes d'un réseau avec ICMP et dont l'adresse réseau est donnée en argument.")
parser.add_argument("-x", metavar="nom du fichier")
args = parser.parse_args()

    
if args.p:
    passive(args.p)
elif args.a:
    print("---> CTRL + pause/Attn pour arreter le SCAN\n\n")
    active(args.a)
elif args.t:
    print("CTRL + pause/Attn pour arreter le SCAN")
    découverte_total(args.t)
        
else:
    print("argument non pris en charge : -h ou --help pour de l'aide")

if args.x:
        resultat(RESULTAT, args.x)       

print("\n! FIN DU PROGRAMME !")
