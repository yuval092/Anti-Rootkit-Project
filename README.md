# Anti-Rootkit Project

This repository holds a tool which detects common beahaviors of rootkits and informs the user of any suspicous activity. 

The main focus of this tool is to detect different hooking techniques,  both in the kernel and in user-space. A rootkit tends to hook different data in the system in order to hide itself or its resources (processes, files, netowk traffic, etc). By detecting such hooks, we can identify whether or not there is a rootkit in the system.


## Features

- User-Mode IAT Hook Detection
- Kernel-Mode IAT Hook Detection
- SSDT Hook Detection
- IDT Hook Detection
- IRP Hook Detection
- Graphic interface


## Project Structure

- C Kernel-Mode Driver
- C# GUI Application (WPF)
- C++ Helper DLL
- Tester Folder


## To Do

- Detect More Hooks (MSR, Inline)
- Detect Process Injection Techniques (DLL Injections, AtomBombing...)
- Detect Evasion Techniques (Process Hollowing, Process Doppelgänging...)


## How I Approached This Project

Books about windows kernel, articles from digital whisper, trying stuff...


## Project Environment

Windows 10 1909 x86