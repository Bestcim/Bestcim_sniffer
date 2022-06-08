'''Developed By Bestcim'''
''' İzin alınmadan paylaşılması yasaktır '''

import socket, sys
from struct import *

class PacketSniffer:
    '''
  gelen paketleri yakalamak için kullanılan Soket Modülü //giden ağ trafiği  0x0003 
    '''
    def __init__(self):
        try:
            self.s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
        except socket.error as msg:
            print ('Soket oluşturulamadı! ' + str(msg[0]) + ' Mesaj ' + msg[1])
            sys.exit()
    
    def recv_pkt(self):
        '''
    
        
     socket.ntohs() --> işlevi 32 bitlik bir tamsayıyı dönüştürür
        ağ siparişinden ana bilgisayar siparişine. Ana bilgisayar siparişi ile aynıysa
        ağ emri, işlev sadece bir noop talimatı yürütür.
        Negatif bir değer iletilirse ntohl() bir OverflowError oluşturacaktır.
        
    
        '''

        while True:
            packet = self.s.recvfrom(65565)
            
            #packet string from tuple
            packet = packet[0]
            eth_len = 14
            eth_header = packet[:eth_len]
            eth = unpack('!6s6sH', eth_header)
            
            eth_proto = socket.ntohs(eth[2])
            
            self.display(
                destination_MAC = self.eth_addr(packet[0:6]), 
                Source_MAC = self.eth_addr(packet[6:12]),
                Protocol = str(eth_proto) 
                )
            
            self._ip_header(packet, eth_len)
          
    def eth_addr(self,_pkt):
        '''
Manipüle etmek için Oluşturulan Paketler

        '''
        _pkt = str(_pkt)
        b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (
            ord(_pkt[0]), ord(_pkt[1]), ord(_pkt[2]), 
            ord(_pkt[3]),ord(_pkt[4]), ord(_pkt[5])
            )
        
        
        return b
        
    def _ip_header(self, packet, eth_len):

       
        ip_header = packet[eth_len:20 + eth_len]
        iph = unpack('!BBHHHBBH4s4s' , ip_header)
        
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_length = ihl * 4

        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])
        
        self.make_dicison(
                    Version = version ,
                    IP_Header_Length = str(ihl),
                    TTL = str(ttl), 
                    Protocol = str(protocol),
                    Source_Address = str(s_addr), 
                    Destination_Address = str(d_addr),
                    iph_length = iph_length,
                    packet = packet,
                    eth_len = eth_len
                )
    
    def tcp_pkt_cap(self, iph_length, eth_length, packet):
        t = iph_length + eth_length
        tcp_header = packet[t:t+20]

        #now unpack them
        '''
       Her paketin kendi onaltılık değerleri vardır.
        bu yüzden struct kullanarak paketleri açtıktan sonra
        bu, belirtildiği gibi C wrapper açılır
        '''
        tcph = unpack('!HHLLBBHHH' , tcp_header)

        source_port = tcph[0]
        dest_port = tcph[1]
        sequence = tcph[2]
        acknowledgement = tcph[3]
        doff_reserved = tcph[4]
        tcph_length = doff_reserved >> 4
        

        h_size = eth_length + iph_length + tcph_length * 4
        data_size = len(packet) - h_size

        #get data from the packet
        data = packet[h_size:]


        print('*' * 30, 'TCP Protocol', '*' * 30)


        self.display(
                        packet_proto='tcp',
                        Source_Port= str(source_port) ,
                        Dest_Port = str(dest_port) ,
                        Sequence_Number = str(sequence) ,
                        Acknowledgement = str(acknowledgement) ,
                        TCP_header_length = str(tcph_length),
                        Data = str(data)
                     )
        
    def icmp_pkt_cap(self, iph_length, eth_length, packet):
        
        
        u = iph_length + eth_length
        icmph_length = 4
        icmp_header = packet[u:u+4]

        #now unpack them :)
        icmph = unpack('!BBH' , icmp_header)

        icmp_type = icmph[0]
        code = icmph[1]
        checksum = icmph[2]
        
        
        h_size = eth_length + iph_length + icmph_length
        data_size = len(packet) - h_size

        #get data from the packet
        data = packet[h_size:]

        print('*' * 30, 'ICMP Protocol', '*' * 30)


        self.display(
                        pakact_proto='icmp',
                        Type = str(icmp_type),
                        Code = str(code),
                        Checksum = str(checksum),
                        Data = str(data)
                    )

    def udp_pkt_cap(self,iph_length, eth_length, packet):
        '''
       Bilgisayar ağlarında, Kullanıcı Datagram Protokolü (UDP) bunlardan biridir.
        İnternet protokol paketinin çekirdek üyeleri. UDP ile bilgisayar
        uygulamalar, bu durumda datagram olarak adlandırılan mesajlar gönderebilir,
        bir İnternet Protokolü (IP) ağındaki diğer ana bilgisayarlara. Önceki iletişimler
        iletişim kanalları veya veri yolları kurmak için gerekli değildir.
        
        '''
        u = iph_length + eth_length
        udph_length = 8
        udp_header = packet[u:u+8]

        #now unpack them :)
        udph = unpack('!HHHH' , udp_header)

        source_port = udph[0]
        dest_port = udph[1]
        length = udph[2]
        checksum = udph[3]


        h_size = eth_length + iph_length + udph_length
        data_size = len(packet) - h_size

        #get data from the packet

        print('*' * 30, 'UDP Protocol', '*' * 30)

        self.display( 
                        SourcePort = str(source_port),
                        Dest_Port = str(dest_port),
                        Length = str(length),
                        Checksum = str(checksum),
                        data = str(packet[h_size:])
                    )
        
    def make_dicison(self, **kargs):
        '''

Programın akışını kontrol etmek için üye işlevi geliştirildi
        böylece çalışma zamanında program kolayca
        paketleri yakalayabilir
        
        '''
        
        proto = {}
        
        for key, val in kargs.items():
            proto[key] = val
           
        protocol = int(proto['Protocol'])
        if protocol == 6:
            self.tcp_pkt_cap(proto['iph_length'], proto['eth_len'], proto['packet'])
            
        elif protocol == 1:
            self.icmp_pkt_cap(proto['iph_length'], proto['eth_len'], proto['packet'])
           
        elif protocol == 17:
            self.udp_pkt_cap(proto['iph_length'], proto['eth_len'], proto['packet'])

        else:
            print("Protokol Eşleşmedi, Hata! %%%% ")
    
    def display(self, **kargs):
        for key,value in kargs.items():
            print(key, value)
            

if __name__ == "__main__":
    packet_sniffer = PacketSniffer()
    packet_sniffer.recv_pkt()