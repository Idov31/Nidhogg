# Nidhogg

![image](https://img.shields.io/badge/C%2B%2B-00599C?style=for-the-badge&logo=c%2B%2B&logoColor=white) ![image](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)

Nidhogg is a multi-functional rootkit for red teams. The goal of Nidhogg is to provide an all-in-one and easy-to-use rootkit with multiple helpful functionalities for red team engagements that can be integrated with your C2 framework via a single header file with simple usage, you can see an [example here](./Example).

Nidhogg can work on any version of x64 Windows 10 and Windows 11.

This repository contains a kernel driver with a C++ header to communicate with it.

**NOTE: Some functionality might trigger PatchGuard, use it at your own risk!**

## Current Features

- Process hiding
- Process elevation
- Process protection (anti-kill and dumping)
- Bypass pe-sieve
- File protection (anti-deletion and overwriting)
- File hiding
- Registry keys and values protection (anti-deletion and overwriting)
- Registry keys and values hiding
- Querying currently protected processes, files, registry keys and values
- Arbitrary kernel R/W
- Function patching
- Built-in AMSI bypass
- Built-in ETW patch
- Process signature (PP/PPL) modification
- Can be reflectively loaded

## PatchGuard triggering features

These are the features known to me that will trigger [PatchGuard](https://en.wikipedia.org/wiki/Kernel_Patch_Protection), you can still use them at your own risk.

- Process hiding
- File protecting

## Basic Usage

It has a very simple usage, just include the header and get started!

```cpp
#include "Nidhogg.hpp"

int main() {
    // ...
    DWORD result = NidhoggProcessProtect(pids);
    // ...
}
```

## Setup

### Building

To compile the project, you will need the following tools:

- [Visual Studio 2022](https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=Community&rel=16)
- [Windows Driver Kit](https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)

Clone the repository and build the driver.

### Driver Testing

To test it in your testing environment run those commands with elevated cmd:

```cmd
bcdedit /set testsigning on
```

After rebooting, create a service and run the driver:

```cmd
sc create nidhogg type= kernel binPath= C:\Path\To\Driver\Nidhogg.sys
sc start nidhogg
```

### Debugging

To debug the driver in your testing environment run this command with elevated cmd and reboot your computer:

```cmd
bcdedit /debug on
```

After the reboot, you can see the debugging messages in tools such as [DebugView](https://learn.microsoft.com/en-us/sysinternals/downloads/debugview).

## Resources

- [Windows Kernel Programming Book](https://github.com/zodiacon/windowskernelprogrammingbook)
- [Kernel Structure Documentation](https://www.vergiliusproject.com)
- [Process Hiding](https://github.com/landhb/HideProcess)
- [Process Elevation](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/how-kernel-exploits-abuse-tokens-for-privilege-escalation)
- [Registry Keys Hiding](https://github.com/JKornev/hidden)
- [Process Signatures](https://github.com/itm4n/PPLcontrol)

## Contributions

Thanks a lot to those people that contributed to this project:

- [BlackOfWorld](https://github.com/BlackOfWorld)
