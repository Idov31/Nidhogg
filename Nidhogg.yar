/*
   YARA Rule Set
   Author: Ido Veltzman
   Date: 2022-06-01
   Identifier: Nidhogg
   Reference: https://github.com/Idov31/Nidhogg
*/

/* Rule Set ----------------------------------------------------------------- */

rule Nidhogg {
   meta:
      description = "Nidhogg rootkit"
      author = "Ido Veltzman"
      reference = "https://github.com/Idov31/Nidhogg"
      date = "2022-06-01"
      
   strings:
      $s1 = "P:\\Nidhogg\\x64\\Release\\Nidhogg.pdb" fullword ascii
      $s2 = "AQAPRQPH" fullword ascii
      $s3 = "\\Device\\Nidhogg" fullword wide
      $s4 = "\\??\\Nidhogg" fullword wide
      $s6 = "0XYZAXAY" fullword ascii
      $s8 = "132583951656873521" ascii
      $s9 = " A_A^_" fullword ascii
      $s10 = "310221000000Z0/1-0+" fullword ascii
      $s11 = "b.reloc" fullword ascii
      $s12 = " A_A^A\\" fullword ascii
      $s13 = "210221153246" ascii
      $s14 = "210221153246Z" fullword ascii
      $s15 = "1325839516568735210" ascii
      $s16 = "31105.6171" fullword wide

      $op0 = { 48 8b d3 48 8b cf e8 a4 c9 ff ff 48 8b 5c 24 30 }
      $op1 = { af 04 4b 65 49 6e 69 74 69 61 6c 69 7a 65 45 76 }
   condition:
      uint16(0) == 0x5a4d and filesize < 13KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}
