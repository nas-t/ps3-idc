/*
 * ps3_analyze_lv2_dump.idc -- Analyzes a PS3 LV2 dump in IDA.
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 * Copyright (C) (makeclean)
 * Copyright (C) nas
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */

#include <idc.idc>
#include "idc.idc"

#include "syscall_names.idh"




static NameHypercalls(void) {
  auto addr, ea, num, lookup, total;

  total=0;
  Message("Looking for hypercalls.. \n");
  Message("This will take some time, please wait... \n");

  for ( ea = 0; ea != 0x800000 && ea != BADADDR;) {
    ea = FindBinary(ea, 1, "44 00 00 22");
    if (ea == BADADDR)
      break;

    num = -1;
    for (lookup = 1; lookup < 48 && num == -1; lookup++) {
      addr = ea - (lookup * 4);
      /* Verify if it's a 'li %r11, XX' instruction */
      if ((Dword(addr) & 0xFFFFFF00) == 0x39600000) {
	num = Dword(addr) & 255;
	break;
      }
    }

    if (num == -1) {
      Message("Failed to find hypercall id at offset 0x%06X\n", ea);
    } else {
      total++;
      MakeComm(ea, form("hvsc(%d): lv1_%s", num, get_hvcall_rawname(num)));
    }
    ea = ea + 4;
  }

  Message("\n*** Finished marking hypercalls. Found %d !\n", total);
}

static CreateOpdStructure(void) {
  auto id;

  Message("Creating structure OPD_s\n");

  id = GetStrucIdByName("OPD_s");
  if (id != -1) {
    Message("Structure OPD_s already exists. Renaming it\n");
    if (SetStrucName(id, "OPD_s_renamed") == 0) {
      Message("Structure OPD_s_renamed already exists. deleting existing structure\n");
      DelStruc(id);
    }
    id = -1;
  }
  id = AddStrucEx(-1, "OPD_s", 0);
  if (id == -1) {
    Message ("Error creating OPD_S structure\n");
    return 0;
  }
  AddStrucMember(id, "base_addr_sub", 0x00, FF_DWRD | FF_DATA, -1, 4);
  AddStrucMember(id, "sub", 0x04, FF_DWRD | FF_0OFF, 0, 4);
  AddStrucMember(id, "base_addr_toc", 0x08, FF_DWRD | FF_DATA, -1, 4);
  AddStrucMember(id, "toc", 0x0C, FF_DWRD | FF_0OFF, 0, 4);
  AddStrucMember(id, "env", 0x10, FF_QWRD | FF_DATA, -1, 8);


  return 1;
}



static CreateTocStructure(void) {
  auto id;

  Message("Creating structure TOC_s\n");

  id = GetStrucIdByName("TOC_s");
  if (id != -1) {
    Message("Structure TOC_s already exists. Renaming it\n");
    if (SetStrucName(id, "TOC_s_renamed") == 0) {
      Message("Structure TOC_s_renamed already exists. deleting existing structure\n");
      DelStruc(id);
    }
    id = -1;
  }
  id = AddStrucEx(-1, "TOC_s", 0);
  if (id == -1) {
    Message ("Error creating TOC_S structure\n");
    return 0;
  }
  AddStrucMember(id, "base_addr_toc", 0x00, FF_DWRD | FF_DATA, -1, 4);
  AddStrucMember(id, "toc", 0x04, FF_DWRD | FF_0OFF, 0, 4);

  return 1;
}


static FindCreatePpuThread_Lv2()
{
  auto addr;
  addr = 0;
  while (addr<0x800000)
  {
    if(Dword(addr) == 0x7D800026)
    {
    	if((Dword(addr+4) == 0xF821FF81) && (Dword(addr+0x34) == 0x61084000) && (Dword(addr+8) == 0xFBC10070))
    	{
    	  Message ("found create_ppu_thread at 0x%x\n\n", addr);
    	  return addr;
    	}
    }
    addr = addr + 4;
  }
  return -1;
}

static FindCreatePpuThread_direct_Lv2()
{
  auto addr;
  addr = 0;
  while (addr<0x800000)
  {
    if(Dword(addr+4) == 0x7C0802A6)
    {
    	if((Dword(addr+8) == 0x550B0632) && (Dword(addr+0xc4) == 0x38FE0FFF))
    	{
    	  Message ("found create_ppu_thread at 0x%x\n\n", addr);
    	  return addr;
    	}
    }
    addr = addr + 4;
  }
  return -1;
}

static NameThreads_Lv2(toc_addr)
{
  auto addr, end, func_addr, func_addr2, jump_target, i, thread_name, thread_offset, r4_step;


  //func_addr = AskAddr(BADADDR, "enter create thread sub address :");
  func_addr = FindCreatePpuThread_Lv2();
  if (func_addr < 0)
      Message ("Error: couldn't find create_ppu_thread\n");
  else
      MakeName(func_addr, "create_ppu_thread");
  
  func_addr2 = FindCreatePpuThread_direct_Lv2();
  if (func_addr < 0)
      Message ("Error: couldn't find create_ppu_thread_direct\n");
  else
      MakeName(func_addr2, "create_ppu_thread_direct");
  
  if(!(func_addr || func_addr2))
      return -1;
  
  

  addr = 0;
  while (addr<0x300000)
  {
  
    if(Byte(addr) == 0x48 || Byte(addr) == 0x4B)
    {
    	jump_target = (((Dword(addr) & 0xFFFFFF) | 0xFF000000 ) + addr - 1) & 0xFFFFFF;
    	if(jump_target == func_addr || jump_target == func_addr2)
    	{
    	    thread_name="";
    	    r4_step=0;
    	    thread_offset=-1;
    	    i=0;
    	    while(i<0x60)
    	    {
    	    	if(r4_step>0)
    	    	{
    	    	    if((Dword(addr-i) & 0xFF000000) == 0xE9000000 && GetOperandValue(addr-i, 0) == r4_step)
    	    	    {
    	    	        thread_offset = Dword(Dword(GetOperandValue(addr-i, 1) + toc_addr + 4) + 4);
    	    	    	//Message("xx %x\n", Dword(Dword(GetOperandValue(addr-i, 1) + toc_addr + 4) + 4));
    	    	    }
    	    	    
    	    	}
    	    
    	    	if((Dword(addr-i) & 0xFFFF0000) == 0xE9220000)
    	    	    thread_name = GetString(Dword(GetOperandValue(addr-i, 1) + toc_addr + 4), -1, 0);
    	    	
    	    	if((Dword(addr-i) & 0xFFFF0000) == 0xE8820000)
    	    	{
		    thread_offset = Dword(Dword(GetOperandValue(addr-i, 1) + toc_addr + 4) + 4);
		}else{
		    if((Dword(addr-i) & 0xFFF0FFFF) == 0xE8800000)
		    {
		        r4_step = (Dword(addr-i) & 0x000F0000) >> 16;
		        Message("r4_step: %d\n", r4_step);
		    }
		}
    	    	i = i + 4;
    	    }
    	    
    	    if(thread_offset>0)
    	    {
    	      if(strlen(thread_name)==0)
    	        thread_name = form("_%x", thread_offset);
    	      MakeFunction(thread_offset, BADADDR);
    	      MakeName(thread_offset, form("_thread_%s", thread_name));
    	      Message("create _thread_%s at 0x%x\n", thread_name, addr);
    	    }else{
    	      Message("failed to find thread: 0x%x\n", addr);
    	    }
    	}
    }

    addr = addr + 4;
  }

}

static CreateToc (toc_addr) {
  auto ea;

  CreateTocStructure();

  MakeName(toc_addr, "TOC");

  Message("Defining TOC entries\n");

  ea = toc_addr - 0x8000;
  while (ea != toc_addr + 0x8000) {
    MakeUnknown(ea, 0x10, DOUNK_SIMPLE);
    MakeStructEx (ea, 0x10, "TOC_s");
    ea = ea + 0x10;
  }
}


static isSyscallTable(addr) {
	if(Qword(Dword(Dword(addr+4)+4)) == 0x3C60800160630003 && Qword(Dword(Dword(addr+124)+4)) == 0x3C60800160630003 && Qword(Dword(Dword(addr+132)+4)) == 0x3C60800160630003 && Qword(Dword(Dword(addr+140)+4)) == 0x3C60800160630003 && Dword(addr) == 0x80000000)
	{
	  if(Dword(Dword(Dword(addr+4)+4)+8) == 0x4E800020 && Qword(Dword(Dword(addr+28)+4)) != 0x3C60800160630003 && Qword(Dword(Dword(addr+556)+4)) == 0x3C60800160630003 && Qword(Dword(Dword(addr+564)+4)) != 0x3C60800160630003)
	    return 1;
	}
	
}


static FindSyscallTable(void) {
  auto ea, syscall_table;

  syscall_table = AskAddr(BADADDR, "If you know the location of the syscall table, "
			  "please enter it.\nOtherwise, press Cancel :");

  /*if (syscall_table != BADADDR) {
    if (isSyscallTable(syscall_table) == 1) {
      Message ("Entered syscall table seems valid, proceding..\n");
    } else {
      Message ("Entered syscall table seems invalid. Will search instead\n");
      syscall_table = BADADDR;
    }
  }*/
  if (syscall_table == BADADDR) {
    Message("Looking for syscall table.. \n");
    Message("This will take some time, please wait... \n");
    for (ea = 0x400000; ea != 0 && ea != BADADDR; ea = ea - 8 ) {
      if ((ea & 0xffff) == 0)
	Message ("Currently at 0x%x\n", ea);
      if (isSyscallTable(ea)) {
	Message ("\n*** Found syscall table at offset 0x%X\n", ea);
	syscall_table = ea;
	break;
      }
    }
    if (syscall_table == BADADDR) {
      Message ("Could not find syscall table in the first 4MB, trying higher memory\n");
      for (ea = 0x400000; ea != 0x800000 && ea != BADADDR; ea = ea + 8 ) {
	if ((ea & 0xffff) == 0)
	  Message ("Currently at 0x%x\n", ea);
	if (isSyscallTable(ea)) {
	  Message ("\n*** Found syscall table at offset 0x%X\n", ea);
	  syscall_table = ea;
	  break;
	}
      }
    }
  }

  return syscall_table;
}

static CreateSyscallTable(syscall_table) {
  auto i, name, syscall_desc, syscall;

  MakeName(syscall_table, "syscall_table");

  Message ("Naming syscall elements\n");

  /* Search last to first to get the not_implemented syscall named correctly as sc0 */
  for (i = 1023; i != -1; i-- )
  {
    name = get_lv2_rawname(i);

    MakeData(syscall_table + 8 * i, FF_DWRD, 4, 0);
    MakeData(syscall_table + 8 * i + 4, FF_DWRD, 4, 0);
    MakeComm(syscall_table + 8 * i + 4, form("Syscall %d", i));
    syscall_desc = Dword(syscall_table + 8 * i + 4);

    MakeData(syscall_desc, FF_DWRD, 4, 0);
    MakeData(syscall_desc + 4, FF_DWRD, 4, 0);
    MakeName(syscall_desc, form("syscall_%s_desc", name));
    syscall = Dword(syscall_desc + 4);
    MakeFunction (syscall, BADADDR);
    MakeName(syscall, form("syscall_%s", name));
  }
}

static main() {
  auto syscall_table, toc;

  syscall_table = FindSyscallTable();

  if (syscall_table == BADADDR) {
    Message ("Could not find the syscall table\n");
    return;
  }

  CreateSyscallTable(syscall_table);

  /* Each syscall entry is a TOC entry, so get the toc pointer stored in it */
  toc = Dword(Dword(syscall_table + 0x04) + 0xC);

  if (toc == BADADDR) {
    Message ("Could not find the TOC\n");
    return;
  }

  Message (form("\n*** Found TOC at : 0x%X\n", toc));
  CreateToc(toc);
  CreateOpd_lv2(toc);

  Message ("\n*** Searching for Threads:\n");
  NameThreads_Lv2(toc);

  Message ("\n*** Searching for Hypercalls:\n");
  NameHypercalls();

  Message ("\n*** All done!!\n");
  Message (form("*** Found syscall table at : 0x%X and labeled 'syscall_table'\n", syscall_table));
  Message (form("*** Found TOC at : 0x%X and labeled 'TOC'\n", toc));
  Message ("*** Don't forget to go to Options->General->Analys\n");
  Message ("*** Then click on the 'Processor specific analysis options' button\n");
  Message (form("*** And set the TOC address to 0x%X (or simply to the symbol 'TOC')\n", toc));

  return;
}
