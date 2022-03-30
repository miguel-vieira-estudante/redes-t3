from grader.tcputils import calc_checksum, str2addr
from iputils import *
import socket

class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.identificador = 0

    def int2ip(self, addr):
        return socket.inet_ntoa(struct.pack("!I", addr))

    def __raw_recv(self, datagrama):
        vihl, dscpecn, tamanho, identification, flags, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)

        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            # TODO: Trate corretamente o campo TTL do datagrama
            next_hop = self._next_hop(dst_addr)
            vihl, dscpecn, tamanho, identification, flags, ttl, proto, \
                checksum, src_addr, dst_addr = struct.unpack('!BBHHHBBHII', datagrama[:20])
            ttl -= 1
            if ttl > 0:
                header = struct.pack('!BBHHHBBHII', vihl, dscpecn, tamanho, identification, flags, ttl, proto, \
                    0, src_addr, dst_addr)
                checksum = calc_checksum(header)
                datagrama = struct.pack('!BBHHHBBHII', vihl, dscpecn, tamanho, identification, flags, ttl, proto, \
                    checksum, src_addr, dst_addr) + payload
            else:
                meu_endereco = str2addr(self.meu_endereco)
                dst_addr = str2addr(self.int2ip(src_addr))

                next_hop = self._next_hop(self.int2ip(src_addr))
                payload = struct.pack('!BBHi', 11, 0, 0, 0)  + datagrama[:28]
                checksum_payload = calc_checksum(payload)
                new_ttl = 64
                payload = struct.pack('!BBHi', 11, 0, checksum_payload, 0) + datagrama[:28]
                checksum_header = calc_checksum(struct.pack('!BBHHHBBH', vihl, dscpecn, 20+len(payload), identification, flags, new_ttl, IPPROTO_ICMP, \
                        0) + meu_endereco + dst_addr)

                datagrama = struct.pack('!BBHHHBBH', vihl, dscpecn, 20+len(payload), identification, flags, new_ttl, IPPROTO_ICMP, \
                        checksum_header) + meu_endereco + dst_addr + payload

            self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dst_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dst_addr).
        # Retorne o next_hop para o dst_addr fornecido.´
        addr, = struct.unpack('!I', str2addr(dst_addr))

        todos_n = self.tabela_encaminhamento.keys()
        todos_n = sorted(todos_n, reverse=True)
        for n in todos_n:
            for ip in self.tabela_encaminhamento[n].keys():
                tamanho = 32 - n

                net, = struct.unpack('!I', str2addr(ip))

                val = net >> tamanho << tamanho
                novo_addr = addr >> tamanho << tamanho

                if val == novo_addr:
                    return self.tabela_encaminhamento[n][ip]

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        self.tabela_encaminhamento = {}
        for t in tabela:
            cidr = t[0]
            next_hop = t[1]
            ip, n = cidr.split('/')
            n = int(n)
            if self.tabela_encaminhamento.get(n):
                self.tabela_encaminhamento[n][ip] = next_hop
            else:
                self.tabela_encaminhamento[n] = { ip: next_hop }

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback
    
    def definir_datagrama(self, segmento, dst_addr):
        vihl = 0x45
        identificador = self.identificador
        self.identificador += 1
        time_to_live = 64
        protocol = IPPROTO_TCP
        src_addr = str2addr(self.meu_endereco)
        dst_addr = str2addr(dst_addr)
        tamanho = 20 + len(segmento)
        header = struct.pack('!BBHHHBBH', vihl, 0, tamanho, 
            identificador, 0, time_to_live, protocol, 0) +  src_addr + dst_addr
        checksum = calc_checksum(header)
        datagrama = struct.pack('!BBHHHBBH', vihl, 0, tamanho, 
            identificador, 0, time_to_live, protocol, checksum) + src_addr + dst_addr + segmento
        return datagrama

    def enviar(self, segmento, dst_addr):
        """
        Envia segmento para dst_addr, onde dst_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dst_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.
        datagrama = self.definir_datagrama(segmento, dst_addr)
        self.enlace.enviar(datagrama, next_hop)
