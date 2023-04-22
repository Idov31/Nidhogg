/*
   YARA Rule Set
   Author: Ido Veltzman
   Date: 2022-07-15
   Reference: https://github.com/Idov31/Nidhogg
*/

/* Rule Set ----------------------------------------------------------------- */

rule Downloads_Nidhogg {
   meta:
      description = "Nidhogg rootkit"
      author = "Ido Veltzman"
      reference = "https://github.com/Idov31/Nidhogg"
      date = "2022-07-15"

   strings:
      $s1 = "PsGetProcessPeb" fullword wide
      $s2 = "AQAPRQPH" fullword ascii
      $s3 = "\\Device\\Nidhogg" fullword wide
      $s4 = "\\??\\Nidhogg" fullword wide
      $s5 = "ZwProtectVirtualMemory" fullword wide
      $s6 = "MmCopyVirtualMemory" fullword wide
      $s7 = "-fffffff" fullword ascii
      $s8 = "0XYZAXAY" fullword ascii
      $s9 = "1325839516568735210" ascii
      $s10 = " A_A^A]A\\_" fullword ascii
      $s11 = "310221000000Z0/1-0+" fullword ascii
      $s12 = "D$0Nidh@" fullword ascii
      $s13 = "210221153246" ascii
      $s14 = " A_A^_" fullword ascii
      $s15 = "L9 t/A" fullword ascii
      $s16 = "132583951656873521" ascii
      $s17 = "b.reloc" fullword ascii
      $s18 = "210221153246Z" fullword ascii
      $s19 = " A_A^A]" fullword ascii
      $s20 = "31105.6171" fullword wide
      $s21 = "CmCallbackReleaseKeyObjectIDEx" fullword ascii
      $s22 = "CmCallbackGetKeyObjectIDEx" fullword ascii

      $op0 = { 48 8b d3 48 8b cf e8 f8 a1 ff ff 48 8b 5c 24 30 }
      $op1 = { af 04 4b 65 49 6e 69 74 69 61 6c 69 7a 65 45 76 }
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}
