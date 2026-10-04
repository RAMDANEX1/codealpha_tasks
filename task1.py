# l'acces  aux interfaces reseau pour capturer le traffic necessite des privileges eleves :
# execution avec sudo 

import struct
import socket

      #### COUCHE LIAISON  #####
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
