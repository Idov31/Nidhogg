/*
   YARA Rule Set
   Author: Ido Veltzman
   Date: 2025-03-18
   Reference: https://github.com/Idov31/Nidhogg
*/

rule Nidhogg {
   meta:
      description = "Nidhogg rootkit"
      author = "Ido Veltzman"
      reference = "https://github.com/Idov31/Nidhogg"
      date = "2025-03-18"

   strings:
      $s1 = "31122.6172" fullword wide
      $s2 = "\\Device\\Nidhogg" fullword wide
      $s3 = "\\??\\Nidhogg" fullword wide
      $s4 = "31105.6171" fullword wide
      $s5 = "\\Driver\\Nsiproxy" fullword wide
      $s6 = "Nidhogg.pdb" fullword wide

      $op1 = { 4C 8D 05 DC 95 00 00 48 8B D0 49 8B CE E8 E1 F4 FF FF }
      $op2 = { 48 8B 55 CF 4C 8D 05 49 AE 00 00 48 8B CE E8 89 0E 00 00 }
      $op3 = { 48 8D 44 24 78 4C 8B C6 49 8B CE 48 89 44 24 20 E8 EE FE FF FF }
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      ( 5 of ($s*) and 2 of ($op*) )
}
