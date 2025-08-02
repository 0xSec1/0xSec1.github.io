---
title: "Buggers v.5 CrackMe"
date: 2025-08-02
categories: [CrackMe,Windows]
tags: [reversing,crackme]
---

# Note
This is my first writeup so it may be a bit confusing to understand and I apologize for that.

## Initial View
At first I checked if the executable is [64bit](https://en.wikipedia.org/wiki/64-bit_computing) or 32bit and confirmed its a 32bit PE([Portable Executable](https://en.wikipedia.org/wiki/Portable_Executable)) using the tool [Detect It Easy](https://github.com/horsicq/DIE-engine/releases).
![32bit_detection](./assets/lib/CrackMe/Buggers/32bit_detection.png)
*Figure 1: Architecture Detection*
So I opened the _buggers.exe_ file and it did nothing and I thought why?? and here I had to use my reversing skill to decode the behaviour. 

## Detailed View

I fired up my [x32dbg](https://x64dbg.com/) and opened _buggers.exe_ in it. 
![initial_view_x32dbg](./assets/lib/CrackMe/Buggers/initial_view_x32dbg.png)
*Figure 2: x32dbg*
Now head over to entry point of program using **Run To User Code** from the toolbar.
![user_code](./assets/lib/CrackMe/Buggers/user_code.png)
First I noticed was a call to [**GetProcAddress**](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress) which returns the address of the specified exported dynamic-link library (DLL) function.
```
FARPROC GetProcAddress(
  [in] HMODULE hModule,		//handle to DLL Module
  [in] LPCSTR  lpProcName	//name of function
);
``` 
![proc_address](./assets/lib/CrackMe/Buggers/proc_address.png)
*Figure 2: GetProcAddress()*

NEXT COME HERE______