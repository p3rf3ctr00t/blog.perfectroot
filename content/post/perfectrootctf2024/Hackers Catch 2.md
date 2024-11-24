---
title: "Hackers Catch 2"
draft: false
Date: 2024-11-23
image: avatar.png
autoimage: yes
description: '0xEpitome'
categories: 'perfectrootctf2024'
Author: '[0xEpitome](https://x.com/0xEpitome)'
comments: true
---

![image](perfectrootctf2024/20241118200045.png)

This challenge was compiled using godot, the aim of this challenge was to collect 14 flags and the enemy would disappear and we will get to the reward.

![image](perfectrootctf2024/20241119231216.png)

![image](perfectrootctf2024/20241119231233.png)

When we get to the 1st enemy:
![image](perfectrootctf2024/20241119231320.png)

2nd enemy:
![image](perfectrootctf2024/20241119231345.png)

It is also important to note when the enemy was touched a life was decreased, to solve this we needed to use cheat engine to modify the value of the flags to be 14/14 before we reach to the enemy, here is how you can do that:

Attach process to cheat engine:
Now in the scan tab:
![image](perfectrootctf2024/20241119231648.png)

We can set the value to 1 since we know the increment of the flags value to be 1 and since it is the first time we are scanning, in the game we collect the first flag and back to cheat engine we click first scan.

![image](perfectrootctf2024/20241119231833.png)

This brings many results, so we search for the next pattern which is 2, and we click next scan, we do this until we find the correct address that holds the flag value.
![image](perfectrootctf2024/20241119231937.png)

These produced less output which we can monitor. At the 3rd flag, we can start changing the values of the addresses, click on first address and add it to the memory view.
![image](perfectrootctf2024/20241119232107.png)

In memory view we can change the value from 3 to 14 now since we found our address
![image](perfectrootctf2024/20241119232222.png)

Now when we collect another flag, we should see the flags value change:
![image](perfectrootctf2024/20241119232308.png)

Here now we can go and collect our reward:
![image](perfectrootctf2024/20241119232358.png)

![image](perfectrootctf2024/20241119232427.png)

`flag: {53ri0u5ly_ju5t_g0_0ut5ide_4nd_t0uch_s0me_gr4ss!}`

I hope you learnt a thing or 2 from the challenges and also enjoyed generally our first CTF. 
See you next time!

![image](perfectrootctf2024/cheers.webp)

## Comments

{{< chat disqus_thread >}}