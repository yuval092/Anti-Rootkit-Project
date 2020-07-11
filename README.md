# Anti-Rootkit Project

This repository holds a tool which detects common beahaviors of rootkits and informs the user of any suspicous activity. 

The main focus of this tool is to detect different hooking techniques,  both in the kernel and in user-space. A rootkit tends to hook different data in the system in order to hide itself or its resources (processes, files, network traffic, etc). By detecting such hooks, we can identify whether or not there is a rootkit in the system.


## Features

- User-Mode IAT Hook Detection
- Kernel-Mode IAT Hook Detection
- SSDT Hook Detection
- IDT Hook Detection
- IRP Hook Detection
- Graphic interface


## Project Structure

- C Kernel-Mode Driver - Responsible For  Detecting Hooks
- C# GUI Application (WPF) - Responsible For Displaying Results
- C++ Helper DLL - Responsible For Communicating With The Driver
- HookDriver Folder - A Tester (Not In Production)


## To Do

- Detect More Hooks (MSR, Inline)
- Detect Process Injection Techniques (DLL Injections, AtomBombing, StackBombing...)
- Detect Evasion Techniques (Process Hollowing, Process Doppelgänging...)


## Project Environment

I wanted my project to be as up to date as possible, so the tested environment for the tool is **Windows 10 1909 x86**.

The reason I chose x86 and not x64 is due to different security mitigations exisiting in Windows x64 such as PatchGuard and DSE. Those mitigations can distrupt both the development and production proceeses. I could bypass those mitigations but that would require modifying the operating system, and changing its intended behavior.
