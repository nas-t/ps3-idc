/*
 * ps3_analyze_fw_sprx.idc -- Analyzes a SPRX, find it's TOC, OPD and import/export structures.
 *
 * Copyright (C) nas
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */

#include "common.idh"

static FindToc(ea, min) {
  auto sub, toc, next_toc, consecutive_tocs;

  consecutive_tocs = 0;

  while (ea<SegEnd(ea)) {
    sub = Dword(ea);
    toc = Dword(ea + 0x04);
    next_toc = Dword(ea + 0x0C);
    //Message("0x%X: 0x%X - 0x%X - 0x%X - %d\n", ea, sub, toc, next_toc, consecutive_tocs);
    if (sub == 0xFFFFFFFF && toc == 0xFFFFFFFF && next_toc == 0xFFFFFFFF)
    	return 0;
    if (toc != 0x00 && toc == next_toc) {
      consecutive_tocs = consecutive_tocs + 1;
      ea = ea + 8;
    } else {
      if(consecutive_tocs>1000)
      Message("end: %x\n", ea);
      if (consecutive_tocs > min  //&&
          //(toc - 0x8000) - (ea + 8) >= 0 &&
          //(toc - 0x8000) - (ea + 8) <= 0x10
          ) {
	MakeName(toc, "TOC");
	break;
      }
      consecutive_tocs = 0;
      ea = ea + 4;
    }
    toc = 0;
  }

  return toc;
}



static FindImportsExports(opd, toc) {
  auto i, ea, module_name, import_start, import_end, export_start, export_end, addr, size, tmp_start, step;
  auto imports, exports, name_ptr, name, fnid_ptr, fnid, stub_ptr, stub, cnt_imports, cnt_exports;

  CreateImportStructure();
  CreateExportStructure();

  Message("Finding Import/Export structure\n");

  for (addr = SegStart(4); addr < SegEnd(4); addr = addr + 4) {

    if(Word(addr) == 0x1c00)
    {
      cnt_imports = 0;
      cnt_exports = 0;
      tmp_start = addr;
      step = 0x1c;
      
      for (ea = addr; ea + 0x1c < SegEnd(addr); ea = ea + step) {
        size = Word(ea);
        if (size != 0x1C00) {
          if(size != 0x2C00)
          {
            if(cnt_imports == 0 && Qword(ea) == 0 && Word(ea+8) == 0x2c00)
            {
              //export_start = 0;
              //break;
              export_end = ea;
              import_start = ea + 8;
              step = 0x2c;
              ea = ea + 8 - step;
            }else{
              import_end = ea;
              export_start = tmp_start;
              break;
            }
          }else{
            cnt_imports = cnt_imports + 1;
          }
        }else{
          cnt_exports = cnt_exports + 1;
        }
      }
    }
    
    if(cnt_imports>0 && cnt_exports>0)
      break;
  }
  
  Message("Found module Import/Export structure\n");

  CreateImports(import_start, import_end);
  CreateExports(export_start, export_end);

  module_name = import_end + 8;
  MakeStr(module_name, BADADDR);
  MakeName(module_name,  "ModuleName");
  Message("Module name is : %s\n", GetString(module_name, -1, ASCSTR_C));

  return ea;
}

static main() {
  auto ea, toc, opd, make_unk, min, seg;
  
  make_unk = AskYN (0, "Do you want to undefine the entire database before continuing?\n"
         "It is recomended to start fresh because IDA can screw up the file otherwise.\n"
         "WARNING: You will loose any work you've done on this file!!");

  if (make_unk == -1) {
    Message("Canceled\n");
    return;
  }

  if (make_unk == 1)
    MakeUnknown(0, BADADDR, DOUNK_SIMPLE);

  ea = ScreenEA();
  ea = NextSeg(FirstSeg());

  min = 10;

  
  Message("\nSearching for TOC:\n");
  while(toc == 0 && min > 3)
  {
    Message("trying min = %d opd_s\n", min);
    toc = FindToc(ea, min);
    min = min - 1;
  }
  
   if (toc != 0) {
    Message("\nFound TOC at 0x%X\n", toc);
    opd = CreateOpd_prx(toc);
    Message("\n*** Finding Import/Export structure\n");
    FindImportsExports(opd, toc);
    Message ("\n*** Searching for Threads:\n");
    NameThreads(FirstSeg(), toc);
    Message ("\n*** Searching for LV2 Syscalls:\n");
    FindLv2Syscalls(FirstSeg());
    RenameSeg(FirstSeg(), ".text");
    RenameSeg(NextSeg(FirstSeg()), ".data");
    MakeName(toc, "TOC");
    Message("\TOC label at 0x%X\n", toc);
    Warning(form("%s\n%s\n%s 0x%X\n%s",
                 "Done.",
                 "Don't forget to go to Options->General->Analysis->"
                 "Processor specific options\n",
                 "And under TOC Address, enter : ", toc,
                 "Then press ok, then Reanalyze program"));
  } else {
    Message("Sorry, couldn't find the TOC");
  }
}
