/*
 * ps3_analyze_ldr.idc -- Analyzes a secure loader file.
 *
 * Copyright (C) nas
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */

#include <idc.idc>

static createFunc(addr, func_name)
{
  auto start;
  
  Message("0x%x: found %s\n", addr, func_name);
  MakeFunction(addr, BADADDR);
  start = GetFunctionAttr(addr,  FUNCATTR_START);
  MakeName(start, func_name);
  
  Message("0x%x: %s\n", start, func_name);
}

static createKey(addr, key_name, key_size)
{

  auto i;
  MakeName(addr, key_name);
  
  for(i=addr;i<(addr+key_size);i=i+0x10)
  {
  	MakeOword(i);
  }
  
  Message("0x%x: %s\n", addr, key_name);
}

static identify_func(seg, func_name, c, b1, b2, b3, b4)
{
  auto i, j, seg_start, seg_end, syscall_name;
  
  seg_start=SegStart(seg);
  seg_end=SegEnd(seg_start);
  
  for(i=seg_start;i<seg_end;i=i+4)
  {
    //Message("0x%x\n", i);
    if(Dword(i)==b1)
    {
      if(c>1)
      {
      	if(Dword(i+4) == b2)
      	{
          if(c>2)
          {
	    if(Dword(i+8) == b3)
	    {
	      if(c>3)
	      {
		if(Dword(i+12) == b4)
		{
		  createFunc(i, func_name);
		  break;
		}
	      }else{
	        createFunc(i, func_name);
	        break;
	      }
	    }
          }else{
            createFunc(i, func_name);
            break;
          }
        }
      }else{
        createFunc(i, func_name);
        break;
      }
    }
  }
}


static find_key(seg, func_name, c, b1, b2, b3, b4)
{
  auto i, j, seg_start, seg_end, syscall_name;
  
  seg_start=SegStart(seg);
  seg_end=SegEnd(seg_start);
  
  for(i=seg_start;i<seg_end;i=i+2)
  {
    //Message("0x%x\n", i);
    if(Dword(i)==b1)
    {
      Message("0x%x\n", i);
      if(c>1)
      {
      	if(Dword(i+4) == b2)
      	{
          if(c>2)
          {
	    if(Dword(i+8) == b3)
	    {
	      if(c>3)
	      {
		if(Dword(i+12) == b4)
		{
		  createKey(i, func_name, c);
		  break;
		}
	      }else{
	        createKey(i, func_name, c);
	        break;
	      }
	    }
          }else{
            createKey(i, func_name, c);
            break;
          }
        }
      }else{
        createKey(i, func_name, c);
        break;
      }
    }
  }
}


static main() {
  auto x, i;
  
  x = FirstSeg();

  for(i=0;i<3;i=i+1)
  {
	identify_func(x, "aes_encrypt", 3, 0x040001A5, 0x34000207, 0x4C004303, 0);
	identify_func(x, "aes_set_encrypt_key", 3, 0x410E8F2A, 0x34004215, 0x410E0EAB, 0);
	identify_func(x, "aes_decrypt", 3, 0x1CFFC310, 0x34000207, 0x0F610304, 0);
	identify_func(x, "aes_set_decrypt_key", 3, 0x0F61018C, 0x3400C09B, 0x40800010, 0);
	identify_func(x, "omac1", 2, 0x7EE010A0 , 0x16E1D01F, 0, 0);
	identify_func(x, "_aes_cbc", 3, 0x4828D121, 0x24002C21, 0x1C042C58, 0);
	identify_func(x, "_aes_ctr", 3, 0x040001D7, 0x32FFFF83, 0x7CFFEB84, 0);
	   
	identify_func(x, "aes_cbc_encrypt", 3, 0x4823C80D, 0xB163068E, 0x2881A88B, 0);


	identify_func(x, "sha1_init", 3, 0x4080000C, 0x3401418B, 0x4133A28F, 0);
	identify_func(x, "sha1_process", 2, 0x41376CB6 , 0x41478DB7, 0, 0);
	identify_func(x, "sha1_update", 2, 0x54C013A4 , 0x0814A852, 0, 0);
	identify_func(x, "sha1_final", 3, 0x3F605FBA, 0x54C01EB8, 0x184E9C3B, 0);
	identify_func(x, "sha1_buffer", 4, 0x24FFC0D0, 0x04000250, 0x24FF80D1, 0x40FFFF04);
	     

	identify_func(x, "sha1_hmac", 4, 0x04000303, 0x24004080, 0x04000386, 0x24FF8081);
	identify_func(x, "sha1_hmac_buffer", 4, 0x1CB00081, 0x3FE00385, 0x40FFFF06, 0x1C080083);
	identify_func(x, "sha1_hmac_final", 2, 0x46170383, 0x28804103, 0, 0);
	identify_func(x, "sha1_hmac_init", 2, 0x3A818385, 0x3B830583, 0, 0);


	identify_func(x, "ecdsa_check", 3, 0x04002884, 0x32FFFFD1, 0x1C080083, 0);
	identify_func(x, "ecdsa_verify", 4, 0x24FEC0D4, 0x040002D3, 0x24FE80D5, 0x24FE40D6);


	identify_func(x, "memcpy", 2, 0x04000190, 0x3FE0020E, 0, 0); //old
	identify_func(x, "memcpy", 4, 0x1403C18C, 0x1403C204, 0x3FE00186, 0x04000683); //new

	identify_func(x, "memcmp", 2, 0x3881038C, 0x0C000703, 0, 0); //new
	identify_func(x, "memcmp", 2, 0x36400102, 0x4820C203, 0, 0); //old
	
	identify_func(x, "memset", 2, 0x41818182, 0x04000187, 0, 0); //new
	identify_func(x, "memset", 3, 0x41818182, 0x3FE00188, 0xB1210202, 0); //old


	//identify_func(addr_in_codeseg, "name", number_of_search_values, search1, search2, search3, search4);
	//identify_func(x, "", 3, 0x, 0x, 0x, 0);
	
	x = NextSeg(x);
  }
  
  
  
  x = NextSeg(FirstSeg());
  
  while(x < NextSeg(x))
  {
  	
	find_key(x, "token_key", 32, 0x34181237, 0x6291371C, 0x8BC756FF, 0xFC611525);
	find_key(x, "token_iv", 16, 0xE8663A69, 0xCD1A5C45, 0x4A761E72, 0x8C7C254E);
	find_key(x, "token_hmac_key", 64, 0xCC30C422, 0x9113DB25, 0x733553AF, 0xD06E8762);
	
	find_key(x, "rvk_prg_key", 32, 0x22628A9E, 0xC4C414D5, 0xB32F2B4B, 0xA4926089);
	find_key(x, "rvk_prg_key", 32, 0x03AF06FD, 0x1CE6DA36, 0x6361682C, 0xDF59F970);
	find_key(x, "rvk_prg_iv", 16, 0xD5D4B8ED, 0x62B6CCA0, 0x249A7977, 0x6E136975);
	find_key(x, "rvk_prg_iv", 16, 0x8B5D7876, 0xF40A9E1E, 0x9AC2B22F, 0x51B60BDF);
	find_key(x, "rvk_prg_pub", 40, 0x51751B9F, 0x1DA58638, 0xD2D99F67, 0xE20A1D4A);
	
	find_key(x, "edat_key", 16, 0xBE959CA8, 0x308DEFA2, 0xE5E180C6, 0x3712A9AE);
	find_key(x, "edat_default_hashkey", 16, 0xEFFE5BD1, 0x652EEBC1, 0x1918CF7C, 0x04D4F011);
	find_key(x, "k_license_dec_key", 16, 0xF2FBCA7A, 0x75B04EDC, 0x1390638C, 0xCDFDD1EE);
	find_key(x, "keyset_app_retail", 96, 0x95F50019, 0xE7A68E34, 0x1FA72EFD, 0xF4D60ED3);
	find_key(x, "keyset_app_npdrm", 96, 0x8E737230, 0xC80E66AD, 0x0162EDDD, 0x32F1F774);
	
	find_key(x, "gpkg_key", 16, 0x2E7B71D7, 0xC9C9A14E, 0xA3221F18, 0x8828B8F8);
	find_key(x, "pup_hmac_key", 64, 0xF491AD94, 0xC6811096, 0x915FD5D2, 0x4481AEDC);
	
	find_key(x, "dat_key", 16, 0x2B7E1516, 0x28AED2A6, 0xABF71588, 0x09CF4F3C);
	find_key(x, "dat_iv", 16, 0x3032ADFC, 0xDE09CFBF, 0xF0A3B352, 0x5B097FAF);
	
	find_key(x, "ldr_key", 32, 0xC0CEFE84, 0xC227F75B, 0xD07A7EB8, 0x46509F93);
	find_key(x, "ldr_iv", 16, 0x47EE7454, 0xE4774CC9, 0xB8960C7B, 0x59F4C14D);

	
	//find_key(x, "key_name", key_size_in_bytes, search1, search2, search2, search2);
	//find_key(x, "", , 0x, 0x, 0x, 0x);
	
	
	x = NextSeg(x);
  }
}