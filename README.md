# Nidhogg

![image](https://img.shields.io/badge/C%2B%2B-00599C?style=for-the-badge&logo=c%2B%2B&logoColor=white) ![image](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)

Nidhogg is a multi-functional rootkit for red teams. The goal of Nidhogg is to provide an all-in-one and easy to use rootkit with multiple helpful functionalities for red team engagements that can be integrated with your own C2 framework via single header file with simple usage, you can see an [example here](./Example).

Nidhogg can work on any version of Windows 10 and Windows 11.

This repository contains a kernel driver with C++ header to communicate with it.

**NOTE: This project is currently on its beta, more features will be released in the coming weeks.**

## Current Features

- Process hiding
- Process elevation
- Anti process kill
- Anti process dumping
- Bypass pe-sieve
- Anti file deletion
- Anti file overwritting

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

- [Visual Studio 2019](https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=Community&rel=16)
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

## Resources

- [Windows Kernel Programming Book](https://github.com/zodiacon/windowskernelprogrammingbook)
- [Kernel Structure Documentation](https://www.vergiliusproject.com)
- [Process Hiding](https://github.com/landhb/HideProcess)
- [Process Elevation](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/how-kernel-exploits-abuse-tokens-for-privilege-escalation)

## Contributions

I'll happily accept contribution, make a pull request and I will review it!
