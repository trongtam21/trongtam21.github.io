---
title: HackTheBox [CrewCrow challenge]
time: 2024-10-23 12:00:00
categories: [CTF]
tags: [CTF,wargame,ddapi]
image: /assets/posts/htbcrewcrow/1.png
---
## Description 
The Cyber Crime Investigation Unit (CCIU) has been tracking a famous cybercriminal organization known as "CrewCrow" for several years. The group is responsible for numerous high-profile cyber-attacks, targeting financial institutions, government agencies, and private corporations worldwide. The elusive leader of CrewCrow, known by the alias "Nefarious," is a master hacker, who has managed to evade the authorities for years. In a major breakthrough, CCIU intercepted communications indicating that Nefarious was planning a significant cyber-attack. Acting swiftly, the unit launched a coordinated operation, to arrest CrewCrow members and seize their equipment. During the raid, agents confiscated several devices, including Nefarious's personal computer.As the top digital forensics analyst in the country, you have been tasked with analyzing the disk image of Nefarious's computer. Your objective is to uncover critical information that could provide insights into CrewCrow's operations, reveal the details of their planned attack, and ultimately bring Nefarious to justice.
## Technical usage
Giải mã database từ ứng dụng zoom.
## Solution
### 1. Identify the conferencing application used by CrewCrow members for their communications.
##### Bài này cung cấp cho ta folder từ ổ C của tên tội phạm, sử dụng FTK imager để xem chi tiết
##### Bên trong chỉ có 1 user là Nefarious, và có 1 file pdf bị khóa bằng mật khẩu ở thư mục Nefarious/Documents/Operations/Pending/ còn lại không có gì khả nghi.
![image](/assets/posts/htbcrewcrow/2.png)

##### Với câu hỏi 'ứng dụng conferencing nào được sử dụng', nó có thể được tìm thấy ở file CrewCrow_Terms_and_Conditions.txt tại `Desktop`. 
![image](/assets/posts/htbcrewcrow/3.png)
> Zoom

### 2. Determine the last time Nefarious used the conferencing application.
##### Để xác định lần cuối cùng Nefarious ta có thể xác định từ lần cuối cùng file thực thi của zoom được chạy từ prefetch folder
##### Sử dụng PEcmd để biết được lần cuối được chạy
![image](/assets/posts/htbcrewcrow/4.png)
> 2024-07-16 09:02:02

### 3. Where is the conferencing application's data stored?
##### Dựa vào các tìm kiếm trên google, mình tìm thấy đường dẫn [này](https://cybersecuritynews.com/zoom-team-chat-decrypted/) chứa câu trả lời cho câu hỏi này
![image](/assets/posts/htbcrewcrow/5.png)
> C:\Users\Nefarious\AppData\Roaming\Zoom\data

### 4. Which Windows data protection service is used to secure the conferencing application's database files?
##### Dựa vào 1 vài nguồn từ trên internet, ta có thể tóm tắt quy trình mã hóa như sau:

```
1. Đăng nhập và nhận kwk
Khi người dùng đăng nhập thành công, Zoom Server gửi về một Key Wrapping Key (kwk).
kwk là khóa riêng biệt cho từng người dùng, chỉ tồn tại tạm thời trong RAM, không lưu trên ổ đĩa.
2. Sinh và bảo vệ main_key
Client tạo một main_key — dùng để mã hóa cơ sở dữ liệu chính (zoomus.enc.db).

main_key được mã hóa bằng DPAPI (Data Protection API) của Windows.

Khóa mã hóa này được lưu trong file cấu hình:
C:\Users\<user>\AppData\Roaming\Zoom\zoom.us.ini
→ dưới biến win_osencrypt_key (mã hóa và base64 hóa).
3. Tạo user_key để mã hóa Team Chat
Zoom sử dụng main_key và kwk để tạo user_key bằng các bước:
- Tính SHA256(main_key)
- Tính SHA256(kwk)
- Ghép 2 hash lại → SHA256 kết quả → Base64 encode
→ user_key dùng để giải/mã Team Chat.
4. Mã hóa cơ sở dữ liệu
```

![image](/assets/posts/htbcrewcrow/23.png)

```
Zoom dùng SQLCipher với cấu hình:
- page size: 1024
- KDF iterations: 4000
```

##### Dựa vào tóm tắt về quy trình mã hóa bên trên ta biết được dịch vụ DPAPI được sử dụng để bảo vệ dữ liệu
> DPAPI

### 5. Determine the sign-in option used by Nefarious.

> Password

### 6. Retrieve the password used by Nefarious
##### Trong folder data có 2 file ta cần chú ý là `zoommeeting.enc.db` (Lưu trữ thông tin liên quan đến các cuộc họp mà người dùng đã tổ chức hoặc tham gia) và `zoomus.enc.db` ( lưu các thông tin phiên đăng nhập, cấu hình cá nhân và dữ liệu định danh tài khoản)
##### Theo như tóm tắt ở Q4 file được mã hóa bằng cách mã hóa với main_key và main_key được mã hóa 1 lần nữa với masterkey(DPAPI)
##### masterkey lại được mã hóa bởi mật khẩu trên máy, vì vậy chúng ta sẽ tìm mật khẩu trên máy đầu tiên.
##### Trước hết trong artifacts có cung cấp cho ta folder `system32/config` -> sử dụng file sam và system để lấy NTLLM hash
##### Dùng công cụ secretsdump của impacket

```
┌──(kali㉿kali)-[~/…/CrewCrow/artifact/impacket/examples]
└─$ python3 secretsdump.py -sam ../../../C/Windows/System32/config/SAM -system ../../../C/Windows/System32/config/SYSTEM LOCAL
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0xf0de9713b9c1ac7565ba04b1d1e311c6
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:5101b3bbd47ca8fa09a377bd6c85b62a:::
Nefarious:1001:aad3b435b51404eeaad3b435b51404ee:42703fb3aeb2716687c641c665d26b3c:::
[*] Cleaning up..
```
##### Tiếp theo dùng john crack hash đã tìm được

```bash
┌──(kali㉿kali)-[~/Downloads/HTB/CrewCrow/C]
└─$ echo "Nefarious:1001:aad3b435b51404eeaad3b435b51404ee:42703fb3aeb2716687c641c665d26b3c:::" > hash                                                                                                     
┌──(kali㉿kali)-[~/Downloads/HTB/CrewCrow/C]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash --format=NT          
Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
ohsonefarious92  (Nefarious)     
1g 0:00:00:00 DONE (2025-06-04 21:59) 1.315g/s 6497Kp/s 6497Kc/s 6497KC/s ohsugar...ohsicks06
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed. 
```
##### Ở đầu ra ta biết được mật khẩu là `ohsonefarious92`
> ohsonefarious92

##### Tiếp tục sử dụng mật khẩu đã có và công cụ dpapi.py để giải mã masterkey trong folder `C:/Users/Nefarious/AppData/Roaming/Microsoft/Protect/`

```bash
┌──(kali㉿kali)-[~/…/CrewCrow/artfact/impacket/examples]
└─$ python3 dpapi.py masterkey -file "../../../C/Users/Nefarious/AppData/Roaming/Microsoft/Protect/S-1-5-21-3675116117-3467334887-929386110-1001/28bbab34-d06e-4372-a633-d924fbab301b" -sid S-1-5-21-3675116117-3467334887-929386110-1001                       
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 28bbab34-d06e-4372-a633-d924fbab301b
Flags       :        5 (5)
Policy      :        0 (0)
MasterKeyLen: 000000b0 (176)
BackupKeyLen: 00000090 (144)
CredHistLen : 00000014 (20)
DomainKeyLen: 00000000 (0)

Password:
Decrypted key with User Key (SHA1)
Decrypted key: 0xb759020c3e3a1c15a2d1863d50ee4b27cbf13552cd51f286e68a3c52f70a52086ce301e9cabbbeed8442c4279f679c94cd9e605e5a79f00b4922c80af7a26382
```
##### Okay, đã tìm thấy masterkey. Tiến hành giải mã main_key
##### Main_key được lưu tại tệp `zoom.us.ini` ở sau `win_osencrypt_key` 
![image](/assets/posts/htbcrewcrow/123.png)
##### Trong đó `ZWOSKEY` là mã định danh ta chỉ cần bỏ nó đi. Chuyển dữ liệu cần giải mã thành hex và dùng mimikatz để giải mã blob
![image](/assets/posts/htbcrewcrow/6.png)

```
mimikatz # dpapi::blob /masterkey:b759020c3e3a1c15a2d1863d50ee4b27cbf13552cd51f286e68a3c52f70a52086ce301e9cabbbeed8442c4279f679c94cd9e605e5a79f00b4922c80af7a26382 /raw:01000000d08c9ddf0115d1118c7a00c04fc297eb0100000034abbb286ed07243a633d924fbab301b00000000020000000000106600000001000020000000c9c7d008ea2f4212f4588482b5d206b2be6e58cab04df4bc408c7ca530a810d1000000000e8000000002000020000000b611f6e2959e7013c9915b4c5e50fd08732402b9f39829aecc6ce1572d276f07300000007de29cdfe8313b7d1869276b5b22cc3766d61a0ca95bde772f4f5e899708f8e2b30621b218599b4c0556d157553c3f0340000000470b56f9edf598a4997a1e2281def7e5a0b5841e09ffc61ef778b42210de5c13056c0316581c0bcfbeceb996bcb292e470a7d8a46405eb77d756f264c639a7a4
**BLOB**
  dwVersion          : 00000001 - 1
  guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
  dwMasterKeyVersion : 00000001 - 1
  guidMasterKey      : {28bbab34-d06e-4372-a633-d924fbab301b}
  dwFlags            : 00000000 - 0 ()
  dwDescriptionLen   : 00000002 - 2
  szDescription      :
  algCrypt           : 00006610 - 26128 (CALG_AES_256)
  dwAlgCryptLen      : 00000100 - 256
  dwSaltLen          : 00000020 - 32
  pbSalt             : c9c7d008ea2f4212f4588482b5d206b2be6e58cab04df4bc408c7ca530a810d1
  dwHmacKeyLen       : 00000000 - 0
  pbHmackKey         :
  algHash            : 0000800e - 32782 (CALG_SHA_512)
  dwAlgHashLen       : 00000200 - 512
  dwHmac2KeyLen      : 00000020 - 32
  pbHmack2Key        : b611f6e2959e7013c9915b4c5e50fd08732402b9f39829aecc6ce1572d276f07
  dwDataLen          : 00000030 - 48
  pbData             : 7de29cdfe8313b7d1869276b5b22cc3766d61a0ca95bde772f4f5e899708f8e2b30621b218599b4c0556d157553c3f03
  dwSignLen          : 00000040 - 64
  pbSign             : 470b56f9edf598a4997a1e2281def7e5a0b5841e09ffc61ef778b42210de5c13056c0316581c0bcfbeceb996bcb292e470a7d8a46405eb77d756f264c639a7a4

 * masterkey     : b759020c3e3a1c15a2d1863d50ee4b27cbf13552cd51f286e68a3c52f70a52086ce301e9cabbbeed8442c4279f679c94cd9e605e5a79f00b4922c80af7a26382
description :
data: 57 32 6b 2b 30 32 47 7a 42 56 65 5a 4b 4a 68 58 73 6e 52 49 71 4e 72 74 72 57 56 55 42 41 76 73 30 67 4c 4e 65 35 32 7a 58 4b 77 3d
```
##### Thấy rằng ta đã trích xuất thành công main_key là 1 chuỗi base64
![image](/assets/posts/htbcrewcrow/7.png)
> W2k+02GzBVeZKJhXsnRIqNrtrWVUBAvs0gLNe52zXKw=

### 7. Find the key derivation function iterations used in the encryption process of the conferencing application's database.
##### Câu trả lời được tóm tắt ở Q4
> 4000

### 8. Find the key derivation function page size used in the encryption process.
##### Câu trả lời được tóm tắt ở Q4
> 1024

### 9. Identify Nefarious email address.
##### Dựa vào main_key đã tìm được, giải mã file zoomus.db bằng cách sử dụng sqlitebrowser 
![image](/assets/posts/htbcrewcrow/8.png)
##### Dán main_key ở dạng base64 vừa tìm được vào ô password và sửa các option khác cho phù hợp
##### Ở bảng zoom_user_account_enc ta có thể thấy được thông tin về tài khoản email của tên tội phạm
![image](/assets/posts/htbcrewcrow/9.png)
> nefarious92@outlook.com

##### Dữ liệu các trường bên trong đã bị mã hóa nên chúng ta không đọc được
![image](/assets/posts/htbcrewcrow/10.png)
##### Nếu muốn đọc được chúng ta có thể trích xuất key và iv từ sha256 của main_key

```python
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from base64 import b64decode

main_key = ""

key = SHA256.new(main_key.encode()).digest()

raw = b64decode(".....")

# Tách IV (12 bytes từ byte 1–12), Tag (cuối cùng 16 bytes), và dữ liệu mã hóa (ciphertext)
iv = raw[1:13]
tag = raw[-16:]
data = raw[19:-16]

cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
plaintext = cipher.decrypt_and_verify(data, tag)

print(plaintext.decode('utf-8'))
```
![image](/assets/posts/htbcrewcrow/11.png)
### 10. What is the Meeting ID?
##### Tương tự như câu hỏi trên, Meeting ID có thể được tìm thấy trong bảng zoom_kv 
![image](/assets/posts/htbcrewcrow/12.png)
##### Để giải mã đươc cột value chúng ta cần sử dụng mã SID 
- Key được tạo từ sha256 của nó.
- IV được tạo từ cách mã hóa sha256 của key và lấy 16 byte đầu 

```python
import hashlib

sid = b"S-1-5-21-3675116117-3467334887-929386110-1001"

# Tính SHA-256 của SID để tạo key
key = hashlib.sha256(sid).digest()

iv = hashlib.sha256(key).digest()[:0x10]

# In ra key và iv dưới dạng hex string, cách nhau bằng dấu cách
print("Key: " + " ".join(format(n, '02x') for n in key))
print("IV:  " + " ".join(format(n, '02x') for n in iv))
```
![image](/assets/posts/htbcrewcrow/13.png)
![image](/assets/posts/htbcrewcrow/14.png)
> ID là 86233834426

### 11. Retrieve the password used to encrypt the plan PDF file from the meeting chat.
##### Giải mã database `zoommeeting.enc.db` theo cách tương tự 
![image](/assets/posts/htbcrewcrow/15.png)
> EOztYmVeUxp6TmV

### 12. Discover the location from which the upcoming cyber-attack will be launched.
##### Quay lại file pdf bị khóa, dùng mật khẩu EOztYmVeUxp6TmV để mở
![image](/assets/posts/htbcrewcrow/172.png)
> Eastern Europe

### Nguồn
https://cellebrite.com/en/part-1-ctf-2022-write-up-marshas-pc/
https://infosecwriteups.com/decrypting-zoom-team-chat-forensic-analysis-of-encrypted-chat-databases-394d5c471e60#04a7