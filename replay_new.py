from random import Random
from scapy.all import *
from Modbus.Modbus import *
import binascii

srcIp = '192.168.10.211'
srcPort = random.randint(1024, 65535)
destIp = '192.168.10.198'
destPort = 502
seqNumber = random.randint(444, 8765432)
ackNr = 0
transId = random.randint(44, 44444)

def updateSeqAndAckNrs(sendPkt, recvPkt):
    global seqNumber
    global ackNr
    print(f"DEBUG: {recvPkt}")
    seqNumber = seqNumber + len(sendPkt [TCP].payload)
    if TCP in recvPkt:
        ackNr = ackNr + len(recvPkt [TCP].payload)

def sendAck():
    ip = IP(src=srcIp, dst=destIp)
    ACK = TCP(sport=srcPort, dport=destPort, flags='A', seq=seqNumber, ack=ackNr)
    pktACK = ip / ACK
    send(pktACK)

def tcpHandshake():
    global seqNumber
    global ackNr

    ip = IP(src=srcIp, dst=destIp)
    SYN = TCP(sport=srcPort, dport=destPort, flags='S', seq=seqNumber, ack=ackNr)
    pktSYN = ip / SYN

    pktSYNACK = sr1(pktSYN)
    print(f"HANDSHAKE DEBUG: {pktSYNACK.seq}")

    ackNr = pktSYNACK.seq + 1
    print(f"ACKNOWLEDGEMENT NUMBER: {ackNr}")
    seqNumber = seqNumber + 1
    ACK = TCP(sport=srcPort, dport=destPort, flags='A', seq=seqNumber, ack=ackNr)

    send(ip/ACK)
    return ip/ACK

def endConnection():
    ip = IP(src=srcIp, dst=destIp)
    RST = TCP(sport=srcPort, dport=destPort, flags='RA', seq=seqNumber, ack=ackNr)
    pktRST = ip / RST
    send(pktRST)

def connectedSend(pkt):
    pkt[TCP].flags = 'PA'
    pkt[TCP].seq = seqNumber
    pkt[TCP].ack = ackNr
    send(pkt)

connectionPkt = tcpHandshake()

ModbusPkt = connectionPkt/ModbusADU()/ModbusPDU01_Read_Coils()

ModbusPkt[ModbusADU].uintId = 1

ModbusPkt[ModbusPDU01_Read_Coils].funcCode = 1
ModbusPkt[ModbusPDU01_Read_Coils].quantity = 5

#data = [binascii.unhexlify('747827338a99e063dad6ffc9080045000033d62c40004006cda6c0a80ad3c0a80ace01f6da84474a0365ad2f621750183e8060d600000000000000050103020040'),
#        binascii.unhexlify('747827338a99e063dad6ffc9080045000033d62d40004006cda5c0a80ad3c0a80ace01f6da84474a0370ad2f622350183e8060bf00000000000000050103020040')]


data = [binascii.unhexlify('747827338a99e063dad6ffc9080045000034d62b40004006cda6c0a80ad3c0a80ace01f6da84474a0364ad2f620b80123e8064310000020405b40402030300010101'), 
        binascii.unhexlify('747827338a99e063dad6ffc9080045000033d62c40004006cda6c0a80ad3c0a80ace01f6da84474a0365ad2f621750183e8060d600000000000000050103020040'),
        binascii.unhexlify('747827338a99e063dad6ffc9080045000033d62d40004006cda5c0a80ad3c0a80ace01f6da84474a0370ad2f622350183e8060bf00000000000000050103020040')]


for i in range(len(data)):
    ModbusPkt[ModbusADU].transId = transId + i*3
    ModbusPkt[ModbusPDU01_Read_Coils].startAddr = random.randint(0, 65535)
    raw_pkt = data[i]
    
    Modbus_pkt = Ether(raw_pkt)

    print("SENDING PACKET")
    #connectedSend(ModbusPkt)
    connectedSend(Modbus_pkt)

    print("SNIFFING FOR RESPONSE...")
    Results = sniff(count=1, iface='Ethernet')
    #Results = sniff(count=1, filter='tcp[tcpflags] & (tcp-push|tcp-ack) != 0')
    print("SNIFFED RESPONSE: ", Results)
    ResponsePkt = Results[0]
    
    updateSeqAndAckNrs(ModbusPkt, ResponsePkt)
    ResponsePkt.show()
    print("SENDING ACKNOWLEDGEMENT")
    sendAck()

print("ENDING CONNECTION")
endConnection()

