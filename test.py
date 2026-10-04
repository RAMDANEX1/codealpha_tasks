import socket
import struct

# Convertit une adresse MAC en format lisible (AA:BB:CC:DD:EE:FF)
def formater_mac(octets_mac):
    octets_str = map('{:02x}'.format, octets_mac)
    return ':'.join(octets_str).upper()

# 1. COUCHE LIAISON : Décodage de la Trame Ethernet (14 octets)
def decoder_ethernet(donnees):
    mac_dst, mac_src, ethertype = struct.unpack('>6s6sH', donnees[:14])
    return formater_mac(mac_dst), formater_mac(mac_src), socket.htons(ethertype), donnees[14:]

# 2. COUCHE RÉSEAU : Décodage du Paquet IPv4 (20 octets min)
def decoder_ipv4(donnees):
    version_ihl = donnees[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0xF) * 4 # Longueur réelle de l'en-tête IP
    
    ttl, proto, src, dst = struct.unpack('>BBH4s4s', donnees[8:20])[0], \
                           struct.unpack('>BBH4s4s', donnees[8:20])[1], \
                           socket.inet_ntoa(donnees[12:16]), \
                           socket.inet_ntoa(donnees[16:20])
    
    return version, ihl, ttl, proto, src, dst, donnees[ihl:]

# 3. COUCHE TRANSPORT : Décodage TCP (20 octets min)
def decoder_tcp(donnees):
    port_src, port_dst, seq, ack, offset_reserved_flags = struct.unpack('>HHLLH', donnees[:14])
    offset = (offset_reserved_flags >> 12) * 4 # Longueur en-tête TCP
    flags = offset_reserved_flags & 0x3F # Les 6 drapeaux (FIN, SYN, RST, PSH, ACK, URG)
    
    flag_syn = (flags & 0x02) >> 1
    flag_ack = (flags & 0x10) >> 4
    flag_fin = flags & 0x01
    
    return port_src, port_dst, seq, ack, flag_syn, flag_ack, flag_fin, donnees[offset:]

# 3. COUCHE TRANSPORT : Décodage UDP (8 octets)
def decoder_udp(donnees):
    port_src, port_dst, longueur = struct.unpack('>HHH', donnees[:6])
    return port_src, port_dst, longueur, donnees[8:]

# BOUCLE PRINCIPALE DE CAPTURE
def lancer_sniffer():
    # Socket brut pour intercepter TOUTES les trames Ethernet
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    print("[*] Sniffer réseau démarré... (Ctrl+C pour arrêter)\n")

    try:
        while True:
            donnees_brutes, _ = conn.recvfrom(65535)

            # --- DÉCAPSULATION COUCHE 2 (Ethernet) ---
            mac_dst, mac_src, ethertype, payload_ip = decoder_ethernet(donnees_brutes)

            # 0x0800 = Protocole IPv4 dans EtherType
            if ethertype == 8:
                # --- DÉCAPSULATION COUCHE 3 (IPv4) ---
                version, ihl, ttl, proto, ip_src, ip_dst, payload_transport = decoder_ipv4(payload_ip)
                
                print(f"\n[TRAME ETHERNET] {mac_src} -> {mac_dst} | EtherType: IPv4")
                print(f" └── [PAQUET IP v{version}] {ip_src} -> {ip_dst} | TTL: {ttl} | Protocole: {proto}")

                # --- DÉCAPSULATION COUCHE 4 (TCP / UDP / ICMP) ---
                if proto == 6: # TCP
                    p_src, p_dst, seq, ack, syn, ack_f, fin, payload_app = decoder_tcp(payload_transport)
                    print(f"      └── [SEGMENT TCP] Port {p_src} -> {p_dst} | SEQ: {seq} ACK: {ack} | Flags: [SYN={syn}, ACK={ack_f}, FIN={fin}]")
                    if payload_app:
                        print(f"           └── [DONNÉES APP] {len(payload_app)} octets transportés")

                elif proto == 17: # UDP
                    p_src, p_dst, lg, payload_app = decoder_udp(payload_transport)
                    print(f"      └── [DATAGRAMME UDP] Port {p_src} -> {p_dst} | Longueur: {lg}")

                elif proto == 1: # ICMP
                    print(f"      └── [PAQUET ICMP] Ping / Message de contrôle")

    except KeyboardInterrupt:
        print("\n[*] Arrêt du sniffer.")
        conn.close()

if __name__ == "__main__":
    lancer_sniffer()