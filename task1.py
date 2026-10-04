# l'acces  aux interfaces reseau pour capturer le traffic necessite des privileges eleves :
# execution avec sudo 

import struct
import socket

### COUCHE LIAISON  ###
def unpack_ethernet_trame(data):
    # entete dune trame ethernet est de 14 octets
    eth_header = data[:14]
    #decouper 6/6/2 octets
    dest_mac,src_mac,protocole_type = struct.unpack('!6s 6s H',eth_header)
    return(
        format_mac_adress(dest_mac),
        format_mac_adress(src_mac),
        socket.htons(protocole_type), # convertit de l'orde d'octet de la machine vers nombre d'octets du reseau
    )
   # fonction pour traduire les adresse mac en format lisible 
def format_mac_adress(bytes_adr):
    return ":".join(format(b,"02x") for b in bytes)

#### COUCHE RESEAU ###
def unpack_ipv4(data):
    #entete ip minimal =20 octets
    version_ihl = data[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0xF) * 4 # Longueur réelle de l'en-tête IP
    
    ttl, proto, src, dst = struct.unpack('>BBH4s4s', data[8:20])[0], \
                           struct.unpack('>BBH4s4s', data[8:20])[1], \
                           socket.inet_ntoa(data[12:16]), \
                           socket.inet_ntoa(data[16:20])
    return version, ihl, ttl, proto, src, dst, data[ihl:]

### COUCHE TRANSPORT proto TCP (20 octets min )###
def unpack_tcp(donnees):
    # Utilisation de 'I' (4 octets) à la place de 'L' pour seq et ack
    port_src, port_dst, seq, ack, offset_reserved_flags = struct.unpack('>HHIIH', donnees[:14])
    
    offset = (offset_reserved_flags >> 12) * 4  # Longueur en-tête TCP
    flags = offset_reserved_flags & 0x3F        # Les 6 drapeaux (FIN, SYN, RST, PSH, ACK, URG)
    
    flag_syn = (flags & 0x02) >> 1
    flag_ack = (flags & 0x10) >> 4
    flag_fin = flags & 0x01
    
    return port_src, port_dst, seq, ack, flag_syn, flag_ack, flag_fin, donnees[offset:]
###  COUCHE TRANSPORT proto UDP 8 octets header)
def decoder_udp(donnees):
    port_src, port_dst, longueur = struct.unpack('>HHH', donnees[:6])
    return port_src, port_dst, longueur, donnees[8:]
