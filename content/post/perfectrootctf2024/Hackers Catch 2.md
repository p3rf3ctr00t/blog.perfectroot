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

![[Pasted image 20241118200045.png]]
<br>
- This challenge was compiled using godot, the aim of this challenge was to collect 14 flags and the enemy would disappear and we will get to the reward.
<br>
![[Pasted image 20241119231216.png]]
<br>
![[Pasted image 20241119231233.png]]
<br>
- When we get to the 1st enemy:
<br>
![[Pasted image 20241119231320.png]]
<br>
- 2nd enemy:
<br>
![[Pasted image 20241119231345.png]]
<br>
- It is also important to note when the enemy was touched a life was decreased, to solve this we needed to use cheat engine to modify the value of the flags to be 14/14 before we reach to the enemy, here is how you can do that.
1. Attach process to cheat engine:<br>
Now in the scan tab:
<br>
![[Pasted image 20241119231648.png]]
<br>

2. We can set the value to 1 since we know the increment of the flags value to be 1 and since it is the first time we are scanning, in the game we collect the first flag and back to cheat engine we click first scan.
<br>
![[Pasted image 20241119231833.png]]
<br>

3. This brings many results, so we search for the next pattern which is 2, and we click next scan, we do this until we find the correct address that holds the flag value.
<br>
![[Pasted image 20241119231937.png]]
<br>

- These produced less output which we can monitor. At the 3rd flag, we can start changing the values of the addresses, click on first address and add it to the memory view.
<br>
![[Pasted image 20241119232107.png]]
<br>

4. In memory view we can change the value from 3 to 14 now since we found our address
<br>
![[Pasted image 20241119232222.png]]
<br>
- Now when we collect another flag, we should see the flags value change:
<br>
![[Pasted image 20241119232308.png]]
<br>

5. Here now we can go and collect our reward:
<br>
![[Pasted image 20241119232358.png]]
<br>
![[Pasted image 20241119232427.png]]
<br>
```bash
flag: {53ri0u5ly_ju5t_g0_0ut5ide_4nd_t0uch_s0me_gr4ss!}
```

- I hope you learnt a thing or 2 from the challenges and also enjoyed generally our first CTF. 
See you next time!
<br>
<br>
![image](perfectrootctf2024/cheers.webp)
<br>
## Comments

{{< chat disqus_thread >}}