import csv
#ddos_ip,exceed_size_ips,FloodIps,multipleScan,unsolicatedArp,largeDNS,excessICMP
def calculateMDP(rule):
    MDP_SCORE=0
    for rules in rule:
        if(rules==1):
            MDP_SCORE+=10
    return MDP_SCORE        
 
        

def generateReport(ipMacs,NSPs,ddos_ip,exceed_size_ips,FloodIps,multipleScan,unsolicatedArp,largeDNS,excessICMP):
    with open("report.csv",'w+') as file:
        file.writelines("IP\t\tMAC\t\t\tNSP\tDDOS\tExceedingIPs\tSYN-flood-ip\tMultiport-scan\tUnsolicated-ARP\tlarge-DNS  Excess-ICMP      MDP(%)\n")
        for ip,mac in ipMacs.items():
            rule=[]
            rule.append(1 if ip in NSPs else 0)
            rule.append(1 if ip in ddos_ip else 0)
            rule.append(1 if ip in exceed_size_ips else 0)
            rule.append(1 if ip in FloodIps else 0)
            rule.append(1 if ip in multipleScan else 0)
            rule.append(1 if ip in unsolicatedArp else 0)
            rule.append(1 if ip in largeDNS else 0)
            rule.append(1 if ip in excessICMP else 0)
            MDP_SCORE=calculateMDP(rule)
            file.writelines(f"{ip}\t{mac}\t{rule[0]}\t{rule[1]}\t\t{rule[2]}\t\t{rule[3]}\t\t{rule[4]}\t\t{rule[5]}\t\t{rule[6]}\t{rule[7]}\t\t{MDP_SCORE}\n")
        file.close()
            
        
