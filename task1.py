# l'acces  aux interfaces reseau pour capturer le traffic necessite des privileges eleves :
# execution avec sudo 

import struct
import socket

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


def unpack_ipv4(data):
    #entete ip minimal =20 octets
    vesrion_header_length = data[0]



def format_ip_adress(address):
    return ":".join(str(b) for b in address)