from modules import load
from modules import writeCSV
import sys
fileName=sys.argv[1]
packets=load.loadPcap(fileName)
ipMacs=load.findIpAndMac(packets)

ips=set()
for packet in packets:
    ips.add(load.detectNSP(packet))

ddos_ip=load.detectDDOS(packets)

exceed_size_ips=load.checkSize(packets)

FloodIps=load.detectSynFlood(packets)

multipleScan=load.portScanning(packets);

unsolicatedArp=load.detectUnsolicitedARP(packets)

largeDNS=load.detectLargeDNSResponses(packets)

excessICMP=load.detectExcessiveICMPEcho(packets)

writeCSV.generateReport(ipMacs,ddos_ip,exceed_size_ips,FloodIps,multipleScan,unsolicatedArp,largeDNS,excessICMP)

