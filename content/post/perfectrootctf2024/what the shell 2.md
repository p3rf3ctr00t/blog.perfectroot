---
title: "What the shell 2"
draft: false
Date: 2024-11-23
image: avatar.png
autoimage: yes
description: '0xEpitome'
categories: 'perfectrootctf2024'
Author: '[0xEpitome](https://x.com/0xEpitome)'
comments: true
---

![[Pasted image 20241118195933.png]]

- For this it was an exe file,  
## Unintented Solve
- The easiest way to solve this was through checking the processes created by the file on procmon. Process Monitor(procmon) is an advanced monitoring tool for Windows that shows real-time file system, Registry and process/thread activity.
- You can get procmon [here](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- In procmon set filter:
<br>
![[Pasted image 20241119221243.png]]
<br>
- When we run the file, we should see some activity on procmon:
<br>
![[Pasted image 20241119221407.png]]
<br>
- We can see it opens a message box saying "Hey, welcome to part two", also in procmon we see activity, going to process tree in procmon:
<br>
![[Pasted image 20241119221543.png]]
<br>
- We see the exe file has 2 sub-processes with the most interesting being powershell child process, in this process: 
<br>
![[Pasted image 20241119221723.png]]
<br>
- The following command is being ran on the background:
```
powershell.exe -EncodedCommand JABUAGUAbQBwAFAAYQB0AGgAIAA9ACAAWwBTAHkAcwB0AGUAbQAuAEkATwAuAFAAYQB0AGgAXQA6ADoARwBlAHQAVABlAG0AcABQAGEAdABoACgAKQA7ACAAJABGAGkAbABlAFAAYQB0AGgAIAA9ACAAIgAkAFQAZQBtAHAAUABhAHQAaABcAFwAZgBsAGEAZwAuAHQAeAB0ACIAOwAgACIASABlAHIAZQAgAGkAcwAgAHkAbwB1AHIAIABmAGwAYQBnACAAewBBAF8AVgAzAHIAeQBfAE4AMAAxAHMAeQBfAFMAaAA0AGwAbABjADAAZAAzAF8AMwA5AGYANwA3AGUAZgA3ADcAYQA5ADQANQAwADEANgA3ADgAOABkAGUAYgBhADAAOABlADkAZABkADAANAA1ADYAMABjAGEAYwBlAGMAZgAxADcAYgA4ADQANQAyADQAMQBiADcANABjAGMAOQBhAGYANQBkAGUAMQAyAGYAZABkADAANgBmAGQAMwA2ADgAZQA1AGIANwBmADMAYQAyAGIANQA1AGEAMQA1ADYANQAxAGUAMAAxAGQAMwA5ADkAZgBhAGYAMwAzADQANAAyAGIAZgAzADQANAAyADYAZgBhADAAMQA4ADUAOQBhADcANQA0ADIAMAA0AGIAYwA4AH0AIgAgAHwAIABPAHUAdAAtAEYAaQBsAGUAIAAtAEYAaQBsAGUAUABhAHQAaAAgACQARgBpAGwAZQBQAGEAdABoAA==
```

- Decoded the base64 code in cyberchef and remove null bytes:
<br>
![[Pasted image 20241119221922.png]]
<br>
- We get our flag.

## Intended Solve
- For the intended we will use x64dbg to debug our exe file and extract the shellcode.
- Most of the shellcodes, they are stored in 3 areas mostly .text, .rsrc and .data sections of a PE file, this can be confirmed in [pestudio]([Winitor](https://www.winitor.com/download)):
<br>
![[Pasted image 20241119222819.png]]
<br>
- It is also good to note that, we can also see the functions used by the exe in pestudio:
<br>
![[Pasted image 20241119222924.png]]
<br>
- The flags with x are the most relevant and these functions show the classic pattern of shellcode injection, hence another indicator the exe has a shellcode. 
- We can extract the shellcode now in x64dbg. in x64dbg go to memory map and look for our executable. Since we already 3 memory regions, we should look for the one with read, write, execute which is the .data section
<br>
![[Pasted image 20241119224842.png]]
<br>
- To dump it we follow it in dump as save it as a .bin file so as to use the scdbg
<br>
![[Pasted image 20241119224952.png]]
<br>
- We can already see hints of powershell encoded command as the one seen on procmon, copy the whole data go to binary, save to a file, I saved mine to flag.bin.
- Now we use scdbg as our whattheshell1 code and we should get our flag
```bash
flag: {A_V3ry_N01sy_Sh4llc0d3_39f77ef77a945016788deba08e9dd04560cacecf17b8  
45241b74cc9af5de12fdd06fd368e5b7f3a2b55a15651e01d399faf33442bf34426fa01859a754204bc8}
```

## Comments

{{< chat disqus_thread >}}