from scapy.all import *

class TestPLF1(Packet):
    fields_desc=[ FieldLenField("len", None, count_of="plist"),
    #PacketListField("plist", None, IP, count_from=lambda pkt:pkt.len) ]
    PacketListField("plist", 0x00,ByteField, count_from=lambda pkt:pkt.len) ]

class TestSLF(Packet):
    fields_desc=[ FieldLenField("len", None, length_of="data"),
    StrLenField("data", "", length_from=lambda pkt:pkt.len) ]

class TestPkt1(Packet):
    fields_desc=[ ByteField('f1',0x00), StrField('s1',"a1"), 
                 StrLenField("s1","",length_from=lambda pkt: pkt.len),
                ByteField('type',0x00)]

def vlenq2str(l):
    s = []
    s.append(l & 0x7F)
    l = l >> 7
    while l > 0:
        s.append( 0x80 | (l & 0x7F) )
        l = l >> 7
    s.reverse()
    return bytes(bytearray(s))

def str2vlenq(s=b""):
    i = l = 0
    while i < len(s) and ord(s[i:i+1]) & 0x80:
        l = l << 7
        l = l + (ord(s[i:i+1]) & 0x7F)
        i = i + 1
    if i == len(s):
        warning("Broken vlenq: no ending byte")
    l = l << 7
    l = l + (ord(s[i:i+1]) & 0x7F)

    return s[i+1:], l

class VarLenQField(Field):
    """ variable length quantities """
    __slots__ = ["fld"]

    def __init__(self, name, default, fld):
        Field.__init__(self, name, default)
        self.fld = fld

    def i2m(self, pkt, x):
        if x is None:
            f = pkt.get_field(self.fld)
            x = f.i2len(pkt, pkt.getfieldval(self.fld))
            x = vlenq2str(x)
        return raw(x)

    def m2i(self, pkt, x):
        if s is None:
            return None, 0
        return str2vlenq(x)[1]

    def addfield(self, pkt, s, val):
        return s+self.i2m(pkt, val)

    def getfield(self, pkt, s):
        return str2vlenq(s)

class TestProto2(Packet):
    name = "Proto2"
    fields_desc = [ VarLenQField("len", None, "data"),
                    StrLenField("data", "", length_from=lambda pkt: pkt.len) ,
                    ByteField('field1',0x11), ByteField('type',0x8)
                    ]

if __name__ == '__main__':

    #t1 = TestPkt1(f1=0x11,s1="839383939",type=0x12)
    #print( bytes(t1) )
    #pe = TestPkt1(f1='0x11',len=10,s1="1234567890",type="0x12")/IP(src="10.10.11.2", dst="10.10.11.3")/TCP(flags="S", sport=1234, dport=2345)   
    #print( bytes(pe ) )
    p1 = TestProto2(data='A'*200)/IP(src="10.10.11.2", dst="10.10.11.3")/TCP(flags="S", sport=1234, dport=2345)   
    print( bytes(p1))
    print(" XYZ : ", bytes(p1))
    harr = ('0x' +  bytes(p1).hex(",").replace("," , ",0x")).split(",")
    iarr = [ int(x, base=16)  for x in harr]
    print(" PacketHEX : {} \n PacketINT : {} \n".format(harr, iarr ))

    
    

