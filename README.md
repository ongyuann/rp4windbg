# rp++ as a Windbg Extension: a fast ROP gadget finder for PE/ELF/Mach-O x86/x64/ARM/ARM64 binaries

## Overview

**rp++** or **rp** is a C++ [ROP](https://en.wikipedia.org/wiki/Return-oriented_programming) gadget finder for [PE](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)/[ELF](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)/[Mach-O](https://en.wikipedia.org/wiki/Mach-O) executables and x86/x64/ARM/ARM64 architectures.

![rp4windbg](https://www.youtube.com/watch?v=IlNu48zSeuE)

## Build

You can find shell scripts in [src/build](src/build) for every supported platforms; below is the Linux example:

```
C:\Users\tahai\code\rp4windbg\src\build> .\build-release-msvc.bat

C:\Users\tahai\code\rp4windbg\src\build>cmake ..
-- Selecting Windows SDK version 10.0.22621.0 to target Windows 10.0.19045.
-- Configuring done
-- Generating done
-- Build files have been written to: C:/Users/tahai/Code/rp4windbg/src/build

C:\Users\tahai\code\rp4windbg\src\build>cmake --build . --config RelWithDebInfo
MSBuild version 17.5.1+f6fdcf537 for .NET Framework
[...]
rp-win.vcxproj -> C:\Users\tahai\Code\rp4windbg\src\build\RelWithDebInfo\rp-win.dll
```

## Authors

* Axel '[0vercl0k](https://twitter.com/0vercl0k)' Souchet
* Taha Draidia [tahadraidia](https://twitter.com/tahadraidia) (Ported rp++ to WindDBG)
