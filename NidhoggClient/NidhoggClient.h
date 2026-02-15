#pragma once
#include "pch.h"
#include "NidhoggInterface.h"

#define PRINT_ASCII_ART

#ifdef PRINT_ASCII_ART
constexpr const char* ASCII_ART = R"(                  
                                 8                           
                               38                            
                              988                            
                        90  79888  3                         
                       880 8998880 88                        
                       88899998888088                        
                      7809999999888086                       
                     50899999999888888     0                 
                8     09999999999888888     8                
               83      999999999998880      08               
              08      0899  99999 8880      880              
              88     02  9999999990  3488   488              
              888  88331   0999992  286     880              
             4888     84    99999  90     28887              
              8880      0   22032  8       880               
               888      5   22232  3     8888                
               88888         233        08808                
                  9888        2       8880 9                 
                 988388888        088888888                  
                  88      0883 8881     48                   
                            5888                             
                              8                                                    
)";

void PrintAsciiArt() {
    std::cout << termcolor::bright_magenta << ASCII_ART << termcolor::reset << std::endl;
}
#else
constexpr const char* ASCII_ART = "";

void PrintAsciiArt() { }
#endif