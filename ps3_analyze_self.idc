/*
 * ps3_analyze_self.idc -- Analyzes a SELF file, find it's TOC, OPD and import/export structures.
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 * Copyright (C) nas
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */

#include "common.idh"



static FindToc(opd) {
  auto toc;

  toc = Dword(opd + 0x04);
  MakeName(toc, "TOC");
  return toc;
}

static FindImportsExports() {
  auto ea, seg, size, import_start, import_end, export_start, export_end;

  CreateImportStructure();
  CreateExportStructure();

  for (seg = FirstSeg(); export_start == 0 && NextSeg(seg) != seg; seg = NextSeg(seg)) {
    //if ((SegEnd(seg) - SegStart(seg)) % 0x1C != 0)
    //  continue;

    for (ea = SegStart(seg); ea + 0x1c < SegEnd(seg); ea = ea + 0x1C) {
      size = Word(ea);
      if (size != 0x1C00) {
	export_start = 0;
	break;
      }
      export_start = seg;
    }
  }

  if (export_start != 0)
  {

    export_end = SegEnd(export_start);
    if(isNullSeg(export_start-4))
    {
      RenameSeg(export_start-4, ".lib.ent.top");
      MakeDword(export_start-4);
    }
    RenameSeg(export_start, ".lib.ent");
    CreateExports(export_start, export_end);
    Message("Found Export Table: 0x%X\n", export_start);
  }

  for (seg = export_start; import_start == 0 && NextSeg(seg) != seg; seg = NextSeg(seg)) {
    //if ((SegEnd(seg) - SegStart(seg)) % 0x2C != 0)
    //  continue;

    for (ea = SegStart(seg); ea + 0x2c < SegEnd(seg); ea = ea + 0x2C) {
      size = Word(ea);
      if (size != 0x2C00) {
	import_start = 0;
	break;
      }
      import_start = seg;
    }
  }

  if (import_start == 0)
    return;

  import_end = SegEnd(import_start);
  
  if(isNullSeg(import_start-4) && isNullSeg(import_start-8) && isNullSeg(import_start-12))
  {
    RenameSeg(import_start-12, ".lib.ent.top");
    RenameSeg(import_start-8, ".lib.ent.btm");
    RenameSeg(import_start-4, ".lib.stub.top");
    MakeOffsets(import_start-12, import_start);
  }
  if(isNullSeg(import_start-4) && isNullSeg(import_start-8))
  {
    RenameSeg(import_start-8, ".lib.ent.btm");
    RenameSeg(import_start-4, ".lib.stub.top");
    MakeOffsets(import_start-8, import_start);
  }
  if(isNullSeg(import_end))
  {
    RenameSeg(import_end, ".lib.stub.btm");
    MakeDword(import_end);
  }
  
  RenameSeg(import_start, ".lib.stub");
  Message("Found Import Table: 0x%X\n", import_start);
  CreateImports(import_start, import_end);

  return ea;
}


static main() {
  auto ea, toc, opd, make_unk, seg;

  make_unk = AskYN (0, "Do you want to undefine the entire database before continuing?\n"
         "It is recomended to start fresh because IDA can screw up the file otherwise.\n"
         "WARNING: You will loose any work you've done on this file!!");

  if (make_unk == -1) {
    Message("Canceled\n");
    return;
  }

  if (make_unk == 1)
    MakeUnknown(0, BADADDR, DOUNK_SIMPLE);
  opd = FindOpd();
  if (opd == 0) {
    Message("Could not find the OPD segment\n");
    
    return;
  }
  toc = FindToc(opd);
  
  seg = FirstSeg();
  RenameSeg(seg, ".init");
  RenameSeg(NextSeg(seg), ".text");
  RenameSeg(NextSeg(NextSeg(seg)), ".fini");
  RenameSeg(NextSeg(NextSeg(NextSeg(seg))), ".sceStub.text");
  
  if (toc != 0) {
    Message("\nFound TOC at 0x%X\n", toc);
    RenameSeg(toc, ".toc1");
    RenameSeg(toc - 0x8000, ".got");
    //MakeOffsets(toc - 0x8000, SegEnd(toc - 0x8000));
    FindCtorDtor();
    
    opd = CreateOpd(toc, opd);
    Message("\n*** Finding Import/Export structure\n");
    FindImportsExports();
    
    Message("seg data.rel.ro: %0x%x", SegByBase(SegByName(".data.rel.ro")));
    if(SegByBase(SegByName(".data.rel.ro")))
      MakeOffsets(SegStart(SegByBase(SegByName(".data.rel.ro"))), SegEnd(SegByBase(SegByName(".data.rel.ro"))));
      
    Message ("\n*** Searching for Threads:\n");
    NameThreads(NextSeg(NextSeg(0)), toc);
    Message ("\n*** Searching for LV2 Syscalls:\n");
    FindLv2Syscalls(NextSeg(FirstSeg()));
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
