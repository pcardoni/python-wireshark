import pyshark

cap = pyshark.FileCapture('gprs1201rjo.pcap', display_filter='data.data and tcp.flags.push == 1 and not pptp and not tcp.reassembled.data')


#pkt = cap[24]

def wireshark_data_iso8583(pkt):
    protocol = pkt.transport_layer
    src_ip = pkt.ip.src
    dst_ip = pkt.ip.dst
    src_port = pkt[pkt.transport_layer].srcport
    dst_port = pkt[pkt.transport_layer].dstport
    stream = pkt[pkt.transport_layer].stream
    data = pkt.data.data
    x = 0
    print("Stream: %s" % stream)
    print("Protocol: %s" % protocol)
    print("IP Origem: %s" % src_ip)
    print("IP Destino: %s" % dst_ip)
    print("Porta Origem: %s" % src_port)
    print("Porta Destino: %s" %dst_port)
    print("Tamanho da mensagem ISO: %d" % int(data[:4], 16))
    print("NII da mensagem ISO: %s" % data[6:14])
    print("Tipo da mensagem ISO: %s" % data[16:20])
    bit47_true = False
    while x < len(data):
        if data[x:x + 8] == "ffff0100" and data[x + 10:x + 22] == "303935303730":
            bit47 = bytearray.fromhex(data[x + 24:x + 28]).decode()
            print("Contém Bit47!")
            print("Valor do Bit47: %s "% bit47)
            bit47_true = True
            break
        x += 1
    if bit47_true == False:
        print("Não contém bit47!")
    else:
        return bit47
    print("#############################################################################")
    print()


#for pkt in cap:
#    r = wireshark_data_iso8583(pkt)

r = wireshark_data_iso8583(cap[0])
if r == "None":
    print("Meus ovos")

