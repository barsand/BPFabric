#!/usr/bin/env python
import struct

from core import eBPFCoreApplication, set_event_handler, FLOOD
from core.packets import *

class SimpleSwitchApplication(eBPFCoreApplication):
    @set_event_handler(Header.HELLO)
    def hello(self, connection, pkt):
        self.mac_to_port = {}

        # with open('../examples/packetrewriter.o', 'rb') as f:
        #     print("Installing the eBPF ELF")
        #     connection.send(InstallRequest(elf=f.read()))

        with open('../examples/learningswitch_centralized.o', 'rb') as f:
            print("Installing the eBPF ELF")
            connection.send(InstallRequest(elf=f.read()))

    @set_event_handler(Header.PACKET_IN)
    def packet_in(self, connection, pkt):
        metadatahdr_fmt = 'I10x'
        ethhdr_fmt = '>6s6sH'

        in_port, = struct.unpack_from(metadatahdr_fmt, pkt.data, 0)
        eth_dst, eth_src, eth_type = struct.unpack_from(ethhdr_fmt, pkt.data, struct.calcsize(metadatahdr_fmt))

        connection.send(TableEntryInsertRequest(table_name="rewrite", key=pkt.data, value=struct.pack('I', eth_src)))
        connection.send(PacketOut(data=pkt.data, out_port=out_port))        

        import pdb
        pdb.set_trace()

        # print "\nIN:",
        # print "eth_src: ",
        # print "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB", eth_src)
        # print "eth_dst: ",
        # print "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB", eth_dst)
        # print "in_port: ", in_port+1


if __name__ == '__main__':
    SimpleSwitchApplication().run()
