import pyshark

cap = pyshark.FileCapture('gprs1201rjo.pcap', display_filter='data.data and tcp.flags.push == 1 and not pptp and not tcp.reassembled.data')


#pkt = cap[24]

def wireshark_data_iso8583(pkt):

    data = pkt.data.data
    resultado = {
        "Stream": pkt[pkt.transport_layer].stream,
        "Protocol": pkt.transport_layer,
        "IP Origem": pkt.ip.src,
        "IP Destino": pkt.ip.dst,
        "Porta Origem": pkt[pkt.transport_layer].srcport,
        "Porta Destino": pkt[pkt.transport_layer].dstport,
        "Tamanho Mensagem ISO": int(data[:4], 16),
        "NII Mensagem ISO": data[6:14],
        "Tipo Mensagem ISO": data[16:20]
    }
    x = 0
    y = 1
    bit47_true = False
    while x < len(data):
        if data[x:x + 8] == "ffff0100" and data[x + 10:x + 22] == "303935303730":
            bit47 = bytearray.fromhex(data[x + 24:x + 28]).decode()
            resultado["%d Valor BIT47" % y] = bit47
            bit47_true = True
            y += 1
        x += 1
    resultado["BIT47"] = bit47_true
    return resultado

bit_sim = 0
bit_nao = 0
for pkt in cap:

    r = wireshark_data_iso8583(pkt)
    if r["BIT47"]:
        bit_sim += 1
    else:
        bit_nao += 1
print("Quantos BIT47: %d" % bit_sim)
print("Sem BIT47: %d" % bit_nao)


#r = wireshark_data_iso8583(cap[0])
#print(r)



