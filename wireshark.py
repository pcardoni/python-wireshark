import pyshark

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

inicio = 9
fim = 21
resultado = {}
while inicio < fim:
    arquivo = "" % inicio
    cap = pyshark.FileCapture(arquivo, display_filter='data.data and tcp.flags.push == 1 and not pptp and not tcp.reassembled.data')

    for r in cap:
        l = wireshark_data_iso8583(r)
        if l["BIT47"]:
            variavel = l["1 Valor BIT47"]
            if variavel in resultado:
                temp = resultado[variavel] + 1
                resultado[variavel] = temp
            else:
                resultado[variavel] = 1
    inicio += 1

soma = 0
for r in resultado.keys():
    soma += resultado[r]
print("Resultado")
print()
for p in resultado.keys():
    print("%s: %d - %5.2f" % (p, resultado[p], (100 * resultado[p]) / soma) + "%")
print()
print("Total de mensagem com Bit47: %d" % soma)



