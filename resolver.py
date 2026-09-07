import socket
from dnslib import DNSRecord, QTYPE
from dnslib.dns import RR
from collections import deque, Counter


root_ip = "198.41.0.4"
dns_port = 53
DEBUG = True

# historial de las ultimas 20 consultas recibidas desde clientes
query_history = deque(maxlen=20)
# IP conocida para cada dominio que hemos logrado resolver alguna vez
known_ips = {}
# cache: solo contiene los 3 dominios mas frecuentes dentro del query_history
cache = {}

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

def resolver(mensaje_consulta: bytes, ip_addr=root_ip, ns_name="."):

    qname = str(DNSRecord.parse(mensaje_consulta).get_q().get_qname())

    if DEBUG:
        print(f"(debug) Consultando '{qname}' a '{ns_name}' con dirección IP '{ip_addr}'")


    response = send_dns_query(mensaje_consulta, ip_addr, dns_port)
    parsed_response = parse_DNS_message(response)

    ans = get_A(parsed_response["Answer"])

    if ans is not None:
        return response

    next_ns_name = get_NS(parsed_response["Authority"])

    if next_ns_name is not None:
        ns_ip = get_A(parsed_response["Additional"])
        if ns_ip is not None: #caso c) i
            return resolver(mensaje_consulta, ns_ip, ns_name=next_ns_name)

        ns_query = DNSRecord.question(next_ns_name) #caso c) ii
        ns_query_bytes = bytes(ns_query.pack())
        ns_response = resolver(ns_query_bytes)

        if not ns_response:
            return b""

        parsed_ns_response = parse_DNS_message(ns_response)
        ns_ip = get_A(parsed_ns_response["Answer"])

        if ns_ip is not None:
            return resolver(mensaje_consulta, ns_ip, ns_name=next_ns_name)

    return b"" #caso d)

def build_cached_response(query_bytes, ip):
    #reconstruye una respuesta DNS valida usando la ip que esta guardada en el cache
    query = DNSRecord.parse(query_bytes)
    qname = str(query.get_q().get_qname())
    reply = query.reply()
    reply.add_answer(*RR.fromZone("{} A {}".format(qname, ip)))
    return bytes(reply.pack())

def update_cache(domain):
    # en base al historial de las ultimas 20 consultas, calcula cuales son los 3 dominios que mas se repiten 
    # y los deja en cache con su IP conocida si es que se tiene.
    query_history.append(domain)
    top_3 = []
    for d, cantidad in Counter(query_history).most_common(3):
        top_3.append(d)

    cache.clear()
    for d in top_3:
        if d in known_ips:
            cache[d] = known_ips[d]

def handle_client_query(message: bytes):
    query = DNSRecord.parse(message)
    domain = str(query.get_q().get_qname())

    if domain in cache:
        if DEBUG:
            print(f"(debug) '{domain}' respondido usando cache (IP: {cache[domain]})")
        response = build_cached_response(message, cache[domain])
    else:
        response = resolver(message)
        if response:
            parsed_response = parse_DNS_message(response)
            ip = get_A(parsed_response["Answer"])
            if ip is not None:
                known_ips[domain] = ip

    update_cache(domain)
    return response

IP_VM = "192.168.100.131"
PORT = 8000
BUFF_SIZE = 4096

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

server_socket.bind((IP_VM, PORT))

while True:
    message, client_address = server_socket.recvfrom(BUFF_SIZE)
    response =  handle_client_query(message)
    if response:
        server_socket.sendto(response, client_address)