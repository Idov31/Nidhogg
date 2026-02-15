# Nidhogg

<p align="center">
  <img alt="Logo" src="./images/logo.png">
</p>

![image](https://img.shields.io/badge/C%2B%2B-00599C?style=for-the-badge&logo=c%2B%2B&logoColor=white) ![image](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)

Nidhogg is a multi-functional rootkit to showcase the variety of operations that can be done from kernel space. The goal of Nidhogg is to provide an all-in-one and easy-to-use rootkit with multiple helpful functionalities for operations. Besides that, it can also easily be integrated with your C2 framework.

Nidhogg can work on any version of x64 Windows 10 and Windows 11.

This repository contains a kernel driver with a C++ program to communicate with it.

If you want to know more, check out the [wiki](https://github.com/Idov31/Nidhogg/wiki) for a detailed explanation.

## Current Features

> [!IMPORTANT]  
> All the features have been fully tested up to Windows 11 25H2.
> If you encounter a problem, please open an issue after checking there isn't already an open issue.

- Process hiding and unhiding
- Process elevation
- Process protection (anti-kill and dumping)
- Bypass memory scanners (e.g. [pe-sieve](https://github.com/hasherezade/pe-sieve))
- Thread hiding and unhiding
- Thread protection (anti-kill)
- File protection (anti-deletion and overwriting)
- Registry keys and values protection (anti-deletion and overwriting)
- Registry keys and values hiding
- Listing currently protected or hidden processes, threads, files, ports, registry keys and values
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
- Listing kernel callbacks
  - ObCallbacks
  - Process and thread creation routines
  - Image loading routines
  - Registry callbacks
- Removing and restoring kernel callbacks
- Disabling / Enabling ETW providers (e.g. ETW-TI)
- Module hiding and unhiding
- Driver hiding and unhiding
- Credential Dumping
- Port hiding and unhiding
- Nidhogg Object File (NOF) for kernel-mode COFF execution

## Reflective loading

> [!WARNING]  
> When doing reflective loading, there are features that will be disabled by default and the automatic graceful unload of hidden modules and unhooking callbacks will not work as well.
> It is the user's responsibility to ensure to manually unload any hidden modules upon process termination and unhook any callbacks if the target driver is unloading. Failing to do so may lead to system instability or crashes.

Since version v0.3, Nidhogg can be reflectively loaded with [kdmapper](https://github.com/TheCruZ/kdmapper) but because [PatchGuard](https://en.wikipedia.org/wiki/Kernel_Patch_Protection) will be automatically triggered if the driver registers callbacks, Nidhogg will not register any callback. Meaning, that if you are loading the driver reflectively these features will be disabled by default:

- Process protection
- Thread protection
- Registry operations

## Nidhogg Object File (NOF)

Since version v2.0, Nidhogg has a new capability named "Nidhogg Object File" (NOF) for kernel-mode COFF execution. This means, you can write your own kernel-mode code and compile it to a COFF file which has access to:

- Windows kernel (ntoskrnl) API
- Syscalls
- Nidhogg's API (coming in v2.1)

This feature is **not** compatible with Virtualization Based Security (VBS) as it violates both HVCI and kCFG.

## Script Execution (DEPRECATED IN V2.0)

Since version v1.0, Nidhogg can execute [NidhoggScripts](https://github.com/Idov31/NidhoggScript) - a tool that allows one to execute a couple of commands one after another, thus, creating playbooks for Nidhogg. To see how to write one check out the [wiki](https://github.com/Idov31/NidhoggScript/wiki).

Due to hard maintainability and the fact that it isn't a popular feature, it has been deprecated in version v2.0 and will be removed in the next major release. It will be replaced with another capability named "Nidhogg Object File" (NOF) for kernel-mode COFF execution, which will have access to Nidhogg's API.

## Initial Operations

Since version v1.0, Nidhogg can execute [NidhoggScripts](https://github.com/Idov31/NidhoggScript) as initial operations as well. Meaning, that if it spots the file `out.ndhg` in the root of the project directory (the same directory as the Python file) it will execute the file each time the driver is running.

## PatchGuard triggering features

> [!CAUTION]  
> The following features are known to trigger [PatchGuard](https://en.wikipedia.org/wiki/Kernel_Patch_Protection), you can still use them at your own risk.

- Process hiding
- File protecting
- Driver hiding

## Basic Usage

To see the available commands you can run `NidhoggClient.exe` or look at the [wiki](https://github.com/Idov31/Nidhogg/wiki) for detailed information regarding how to use each command, the parameters it takes and how it works.

```sh
NidhoggClient.exe

# Simple usage: Hiding a process
NidhoggClient.exe process hide 3110
```

## Setup

### Building the client

To compile the client, you will need to have [Visual Studio 2022](https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=Community&rel=16) installed and then just build the project like any other Visual Studio project.

### Building the driver

To compile the project, you will need the following tools:

- [Visual Studio 2022](https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=Community&rel=16)
- [Windows Driver Kit](https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)

Clone the repository and build the project:

```sh
git clone https://github.com/Idov31/Nidhogg.git --recurse-submodules
```

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
- [Credential Dumping](https://github.com/gentilkiwi/mimikatz)
- [Port Hiding](https://github.com/bytecode77/r77-rootkit)
- [Logo](https://hotpot.ai/art-generator)
- [Termcolor](https://github.com/ikalnytskyi/termcolor)

## Contributions

Thanks a lot to those people who contributed to this project:

[![BlackOfWorld](https://avatars.githubusercontent.com/BlackOfWorld?s=60&v=4)](https://github.com/BlackOfWorld)&nbsp;&nbsp;&nbsp;&nbsp;[<img src="https://avatars.githubusercontent.com/0nlyDev?s=40&v=4" width="60" height="60" alt="0nlyDev">](https://github.com/0nlyDev)&nbsp;&nbsp;&nbsp;&nbsp;[<img src="https://pbs.twimg.com/profile_images/1047696480327409664/tGLAvq8d_400x400.jpg" width="60" height="60" alt="SLiNv">](https://x.com/_____vic______)
