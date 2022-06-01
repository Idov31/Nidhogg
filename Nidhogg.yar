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
      $s5 = "0XYZAXAY" fullword ascii
      $s8 = "7.ud5/Richtd5/" fullword ascii
      $s9 = "310221000000Z0/1-0+" fullword ascii
      $s10 = "Q0GW%G" fullword ascii
      $s11 = "6.pd5/" fullword ascii
      $s12 = "210221153246Z" fullword ascii
      $s13 = "4.wd5/td4/{d5/" fullword ascii
      $s14 = "1325839516568735210" ascii
      $s15 = "210221153246" ascii
      $s16 = "0.wd5/" fullword ascii
      $s17 = "[|td5/td5/td5/" fullword ascii
      $s18 = "1.|d5/" fullword ascii
      $s19 = " A_A^A\\" fullword ascii
      $s20 = "132583951656873521" ascii

      $op0 = { 48 8b d3 48 8b cf e8 70 c6 ff ff 48 8b 5c 24 30 }
      $op1 = { af 04 4b 65 49 6e 69 74 69 61 6c 69 7a 65 45 76 }
   condition:
      uint16(0) == 0x5a4d and filesize < 12KB and
      ( 8 of them and all of ($op*) )
}

