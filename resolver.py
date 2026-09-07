import socket
from dnslib import DNSRecord, QTYPE

root_ip = "198.41.0.4"
dns_port = 53

def parse_DNS_message(dns_message: bytes):
    record = DNSRecord.parse(dns_message)

    parsed = {
        "Qname": str(record.get_q().get_qname()),
        "ANCOUNT": record.header.a,
        "NSCOUNT": record.header.auth,
        "ARCOUNT": record.header.ar,
        "Answer": record.rr,
        "Authority": record.auth,
        "Additional": record.ar
    }

    return parsed

def send_dns_query(message, address, port):
     server_address = (address, port)
     sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
     try:
         sock.sendto(message, server_address)
         data, _ = sock.recvfrom(4096)

     finally:
         sock.close()

     return data

def get_A(records):
    for record in records:
        if QTYPE.get(record.rtype) == "A":
            return str(record.rdata)
    return None

def get_NS(records):
    for record in records:
        if QTYPE.get(record.rtype) == "NS":
            return str(record.rdata)
    return None

def resolver(mensaje_consulta: bytes, ip_addr=root_ip):
    response = send_dns_query(mensaje_consulta, ip_addr, dns_port)
    parsed_response = parse_DNS_message(response)

    ans = get_A(parsed_response["Answer"])

    if ans is not None:
        return response

    ns_name = get_NS(parsed_response["Authority"])

    if ns_name is not None:
        ns_ip = get_A(parsed_response["Additional"])
        if ns_ip is not None: #caso c) i
            return resolver(mensaje_consulta, ns_ip)

        ns_query = DNSRecord.question(ns_name) #caso c) ii
        ns_query_bytes = bytes(ns_query.pack())
        ns_response = resolver(ns_query_bytes)

        if not ns_response:
            return b""

        parsed_ns_response = parse_DNS_message(ns_response)
        ns_ip = get_A(parsed_ns_response["Answer"])

        if ns_ip is not None:
            return resolver(mensaje_consulta, ns_ip)

    return b"" #caso d)

IP_VM = "192.168.64.3"
PORT = 8000
BUFF_SIZE = 4096

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

server_socket.bind((IP_VM, PORT))

while True:
    message, client_address = server_socket.recvfrom(BUFF_SIZE)
    response =  resolver(message)
    if response:
        server_socket.sendto(response, client_address)