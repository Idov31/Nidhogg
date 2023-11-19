# Nidhogg

<p align="center">
  <img alt="Logo" src="./images/logo.png">
</p>

![image](https://img.shields.io/badge/C%2B%2B-00599C?style=for-the-badge&logo=c%2B%2B&logoColor=white) ![image](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)

Nidhogg is a multi-functional rootkit for red teams. The goal of Nidhogg is to provide an all-in-one and easy-to-use rootkit with multiple helpful functionalities for red team engagements that can be integrated with your C2 framework via a single header file with simple usage, you can see an [example here](./Example).

Nidhogg can work on any version of x64 Windows 10 and Windows 11.

This repository contains a kernel driver with a C++ header to communicate with it.

## Current Features

- Process hiding and unhiding
- Process elevation
- Process protection (anti-kill and dumping)
- Bypass pe-sieve
- Thread hiding
- Thread protection (anti-kill)
- File protection (anti-deletion and overwriting)
- File hiding
- Registry keys and values protection (anti-deletion and overwriting)
- Registry keys and values hiding
- Querying currently protected processes, threads, files, registry keys and values
- Function patching
- Built-in AMSI bypass
- Built-in ETW patch
- Process signature (PP/PPL) modification
- Can be reflectively loaded
- Shellcode Injection
  - APC
  - NtCreateThreadEx
- DLL Injection
  - APC
  - NtCreateThreadEx
- Querying kernel callbacks
  - ObCallbacks
  - Process and thread creation routines
  - Image loading routines
  - Registry callbacks
- Removing and restoring kernel callbacks
- ETWTI tampering
- Module hiding

## Reflective loading

Since version v0.3, Nidhogg can be reflectively loaded with [kdmapper](https://github.com/TheCruZ/kdmapper) but because [PatchGuard](https://en.wikipedia.org/wiki/Kernel_Patch_Protection) will be automatically triggered if the driver registers callbacks, Nidhogg will not register any callback. Meaning, that if you are loading the driver reflectively these features will be disabled by default:

- Process protection
- Thread protection
- Registry operations

## PatchGuard triggering features

These are the features known to me that will trigger [PatchGuard](https://en.wikipedia.org/wiki/Kernel_Patch_Protection), you can still use them at your own risk.

- Process hiding
- File protecting

## Basic Usage

It has a very simple usage, just include the header and get started!

```cpp
#include "Nidhogg.hpp"

int main() {
    HANDLE hNidhogg = CreateFile(DRIVER_NAME, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    // ...
    DWORD result = Nidhogg::ProcessUtils::NidhoggProcessProtect(pids);
    // ...
}
```

## Setup

### Building the client

To compile the client, you will need to install [CMake](https://community.chocolatey.org/packages/cmake.install/3.13.1) and [Visual Studio 2022](https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=Community&rel=16) installed and then just run:

```sh
cd <NIDHOGG PROJECT DIRECTORY>\Example
mkdir build
cd build
cmake ..
cmake --build .
```

### Building the driver

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
- [Registry Keys Hiding](https://github.com/JKornev/hidden)
- [Process Signatures](https://github.com/itm4n/PPLcontrol)
- [NtCreateThreadEx Hotfix](https://github.com/DarthTon/Blackbone)
- [Logo](https://hotpot.ai/art-generator)

## Contributions

Thanks a lot to those people that contributed to this project:

- [BlackOfWorld](https://github.com/BlackOfWorld)
