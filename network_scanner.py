#!/usr/bin/env python
import scapy.all as scapy
import optparse

def takeArgs():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="range of target Ip address")
    (opt, args) = parser.parse_args()
    if (opt.target == None or opt.target == ""):
        parser.error("[-] Please specify range of target address, use --help for more info.")
    else:
        return opt

def printResult(client_list):
    # Printing result
    print("\n============================================================================================")
    print(" IP\t\t\tAt MAC Address\t\t\tCount")
    print("--------------------------------------------------------------------------------------------")
    for answer in client_list:
        print(" " + answer['ip'] + "  \t" + answer['mac'] + "\t\t" + "1")
        print("--------------------------------------------------------------------------------------------")

def scan(ip):
    #Creating Arp Request
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_brodcast = broadcast/arp_req

    #sending Arp Request
    success_list,error_list = scapy.srp(arp_req_brodcast, timeout=1)

    #Returning Result
    target_client_list = []
    for answer in success_list:
        target_client_dict = {"mac":answer[1].hwsrc, "ip":answer[1].psrc}
        target_client_list.append(target_client_dict)
    return target_client_list

#main body
options = takeArgs()
result = scan(options.target)
printResult(result)
#scapy.ls(scapy.ARP()) this line lists all poarameters of scapy ARP class