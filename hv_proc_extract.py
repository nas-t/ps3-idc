##############################################################
#    HV Process Exrtactor                                    #
#    Copyright 2012 by user                                  #
#    builds elfs of your hv processes                        #
#    contact: a.user<:@>bk.ru                                #
##############################################################

import struct, sys, os.path

def gen_phdr(virtual_addr, phys_addr, virtual_size, phys_size):
    return "000000010000000700000000%08x00000000%08x00000000%08x00000000%08x00000000%08x0000000000010000" % (phys_addr, virtual_addr, virtual_addr, virtual_size, phys_size)

def gen_shdr(virtual_addr, file_addr, size):
    #print "0000000B00000001000000000000000600000000%08x00000000%08x00000000%08x000000000000000000000000000000040000000000000000" % (virtual_addr, file_addr, size)
    return "0000000B00000001000000000000000600000000%08x00000000%08x00000000%08x000000000000000000000000000000040000000000000000" % (virtual_addr, file_addr, size)

elf_header = "7F454C46020201660000000000000000000200150000000100000000800000000000000000000040000000000007D00000000000004000380001004000040000"

if(len(sys.argv)<>3):
    print "\nusage: python "+sys.argv[0]+" <dump file> <firmware version> "
    print "\nsupported firmware: 355, 341, 315 and 260"
    exit(0)

    
hv_bin = sys.argv[1]
hv_ver = sys.argv[2]

fw_proc_table = {'355':0x0035F8D0, '341':0x0035C550, '315':0x0035E850, '260':0x00357C38}

if(hv_ver not in fw_proc_table):
    print "\nunsupported firmware: %s" % (hv_ver)
    print "\nsupported firmware: 355, 341, 315 and 260"
    exit(0)

if(os.path.exists(hv_bin)==True):
    f = open(hv_bin, "rb")
else:
    print "\nfile %s not found!" % (hv_bin)
    exit(0)


proc_id=[]
proc_object=[]
for i in range(32):
    addr=fw_proc_table[hv_ver]+8+(0x10*i)
    f.seek(addr)
    tmp = (struct.unpack('>i',f.read(4))[0] << 8) or struct.unpack('>i',f.read(4))[0]
    #print tmp
    if tmp>0:
        proc_id.append(i)
        proc_object.append(tmp)

#print proc_object

addr_protect_domain=[]
cnt=0
for i in proc_object:
    if cnt>0:
        f.seek(i+0x18)
    else:
        f.seek(i)
    tmp = (struct.unpack('>i',f.read(4))[0] << 8) or struct.unpack('>i',f.read(4))[0]
    #print tmp
    #if tmp>0:
    cnt+=1
    addr_protect_domain.append(tmp)

#print addr_protect_domain

first_page=[]
cnt=0;
for i in addr_protect_domain:
    f.seek(i+0x3c)
    tmp = (struct.unpack('>i',f.read(4))[0])
    if tmp>0:
        first_page.append(tmp)

#print first_page

j=0
for i in first_page:
    address=i
    print "--------------------- Process %i -------------------------" % (proc_id[j])
    #print "first protected page: 0x%x" % (address)
    #o = open(str(proc_id[j])+"_0.bin", "wb")
    elf = open(str(proc_id[j])+".elf", "wb")
    elf.write(elf_header.decode("hex"))
    elf.write("00".decode("hex")*0x7d000)
    segment=0
    seg_start=0
    seg_end=0
    lastea=0x7FFFF000
    seg_start=0x80000000
    elf_pos = 0
    elf_shdr_pos = 0x7D000
    elf_phdr_pos = 0x40
    elf_sect_offset = 0x300
    elf_sect_start = elf_sect_offset
    seg_size = 0
    while address>1:
        f.seek(address)
        ra = (struct.unpack('>i',f.read(4))[0] << 8) or struct.unpack('>i',f.read(4))[0]
        ea = (struct.unpack('>i',f.read(4))[0])
        f.seek(address+16)
        last_page = (struct.unpack('>i',f.read(4))[0])
        next_page = (struct.unpack('>i',f.read(4))[0])
        page_shift=struct.unpack('>i',"\0\0\0" + str(f.read(1)))[0]
        page_size = 2**(page_shift)
        seg_size = seg_size + page_size

        if (((ea & 0xffffffff)-0x1000) <> lastea):

            
            if(seg_start == 0x80000000):
                elf.seek(elf_phdr_pos)
                elf.write(gen_phdr(seg_start, elf_sect_start, seg_size, seg_size).decode("hex"))
                elf_phdr_pos = elf_phdr_pos + 0x38

            #shdr            
            elf.seek(elf_shdr_pos+0x40)
            elf.write(gen_shdr(seg_start, elf_sect_start, seg_size).decode("hex"))
            elf_shdr_pos = elf_shdr_pos + 0x40
            elf_sect_start = elf_sect_offset
            
            seg_end = lastea + page_size - 1
            print "segment %2i ea:0x%08x-0x%08x >> %s" % (segment, seg_start, seg_end, str(proc_id[j])+"_"+str(segment)+".bin")
            segment+=1
            seg_start=(ea & 0xffffffff)
            #print "segment %i start" % (segment)
            #o.close()
            #o = open(str(proc_id[j])+"_"+str(segment)+".bin", "wb")
            
            
        if ra>0 and page_shift>0 and ra<0x800000:
            f.seek(ra)
            elf.seek(elf_sect_offset)
            elf.write(f.read(page_size))
            elf_sect_offset = elf_sect_offset + page_size
            
            f.seek(ra)
            #o.write(f.read(page_size))
        #print "ra:0x%8x ea:0x%x next_page:0x%x page_size:0x%x" % (ra, (ea & 0xffffffff), next_page, page_shift)
        if ((next_page>0 and next_page<0x800000) and (next_page <> address)) and ra>0 and page_shift>0:
            address=next_page
        else:
            if(next_page>0x800000):
                print "WARNING: next page addr outside hv dump: 0x%08x\n (dump too small)" % (address)
            address=0
        lastea = (ea & 0xffffffff)
    #o.close()

    #last shdr
    elf.seek(elf_shdr_pos+0x40)
    elf.write(gen_shdr(seg_start, elf_sect_start, seg_size).decode("hex"))
    elf_shdr_pos = elf_shdr_pos + 0x40
    elf_sect_start = elf_sect_offset
    
    #elf.seek(0x38)
    #elf.write(("%04x" % (segment)).decode("hex"))
    elf.seek(0x3C)
    elf.write(("%04x" % (segment+1)).decode("hex"))
    elf.close()
    j+=1

