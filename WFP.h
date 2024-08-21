#pragma once

#include <windows.h>
#include <fwpmu.h>
#include <stdio.h>
#include <tlhelp32.h>

#pragma comment(lib, "fwpuclnt.lib")

#define EXIT_ON_ERROR(fnName) \
   if (result != ERROR_SUCCESS) \
   { \
      printf(#fnName " = 0x%08X\n", result); \
      goto CLEANUP; \
   }

// Provider info
WCHAR* providerName = L"WFP example";
WCHAR* providerDescription = L"WFP example description";
const GUID providerKey =
{
   0x247a37f3,
   0xaead,
   0x4625,
   { 0x84, 0x77, 0xb9, 0x7d, 0x48, 0x79, 0x3a, 0xb3 }
}; // 247a37f3-aead-4625-8477-b97d48793ab3

// Filters info
WCHAR* filterName = L"WFP Filter example";