import scapy.all as scapy
from argparse import *


def get_ip():
    parser = ArgumentParser()
    parser.add_argument("-i", "--ip", dest="target", help= " NETWORK IP/SUBNET")
    option = parser.parse_args()
    if not option.target:
        parser.error("Please add an IP Network Target like (192.168.1.0/24), --help for more information")
    return option.target

def scan(ip):
    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    response = scapy.srp (packet, timeout= 8, verbose=False) [0]
    response_list = []
    for rp in response:
        dict = {"ip" : rp[1].psrc, "mac" : rp[1].hwsrc}
        response_list.append(dict)
    return(response_list)



def print_result(res):
    print("""                                                        
     #   ##    ####  #    # ###### ###### ###### #####  
     #  #  #  #    # #   #      #      #      #  #    # 
     # #    # #      ####      #      #      #   #    # 
     # ###### #      #  #     #      #      #    #####  
#    # #    # #    # #   #   #      #      #     #   #  
 ####  #    #  ####  #    # ###### ###### ###### #    # """)
    
    print(" =========================================")
    print("  IP \t \t \t MAC Adress \n =========================================")
    for n in res:
        print(f'{n["ip"]} \t \t {n["mac"]}')

input_ip = get_ip()
result_scan = scan(input_ip)
print_result(result_scan)
