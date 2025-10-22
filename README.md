# tryhackme-Extracted-writeue

Room: Extracted (TryHackMe)
Difficulty: Medium

The challenge simulates a scenario where suspicious traffic is observed on a workstation. Due to SIEM ingestion issues, the network capture device is the only source for analysis. The task is to analyze a provided .pcapng file to reconstruct and understand the data exfiltration attack.

Initial File Analysis:

Tool Used: capinfos to get high-level packet capture info.

Timeframe: ~2.5 minutes.

Packets: ~53,000 sent/received.

Observations:

Traffic is exclusively TCP, mostly user data (99.1%).

Single workstation IP 10.10.45.95 involved.

Workstation received ~1MB and sent ~389MB of data.

Traffic mainly directed to ports 1337, 1338, and 1339. Port 1337 carries most of the data.



Traffic Analysis:

Using Wireshark Statistics → Conversations: confirmed the single attacker-target relationship.

Suspicious .ps1 PowerShell script request observed from the workstation.

Using Follow → TCP Stream, the script content is reconstructed.

PowerShell Script Analysis (xxxmmdcclxxxiv.ps1)

Script purpose: Memory dump of KeePass and exfiltration.

Key functionalities:

Procdump Check and Download:

Checks if C:\Tools\procdump.exe exists.

If not, downloads and extracts it from Sysinternals.

KeePass Detection:

Checks if KeePass process is running.

Memory Dump:

Dumps KeePass process memory using Procdump to Desktop\1337.

Waits until Procdump confirms “Dump count reached”.

Data Obfuscation & Encoding:

Memory dump XOR’ed with key 0x41.

Base64-encoded.

Saved as 539.dmp.

Exfiltration:

Sends the dump to attacker IP 10.10.94.106 on port 1337 in 1024-byte chunks.

KeePass Database Dump:

Similar procedure for database (Database1337.kdbx) with XOR key 0x42 and port 1338.

Decoy Comments:

Script contains long obfuscated comments intended to slow analysis; they do not hold actionable data.

Exfiltrated Data Reconstruction

Extraction of network data:

Using tshark to dump TCP payloads to text:

tshark -r traffic.pcapng -T fields -e data -Y "ip.dst == 10.10.94.106" > extracted_payload.txt


Python Script for Decoding:

Steps performed:

Convert hex to binary.

Base64 decode the binary.

XOR with the appropriate key (0x41 for memory dump, 0x42 for database).

Output: reconstructed dump files (reconstructed_dump.bin).


Memory Dump Analysis:
Objective: Extract KeePass master password from memory dump.
https://github.com/vdohney/keepass-password-dumper
Run the tool on the memory dump.
Although the first character is not found, the rest of password is revealed.
That is the answer for the first part.


finding the flag:
We csn use the second dump extracted and look for the keepass database file, but that result in error for me so I physiclly copied the encoded data from wireshark and used a pyhton script to decode and extract the .kdbx file.
import base64

# Base64 encoded string
encoded_string = "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"

# Hexadecimal key
hex_key = 0x42  # Key 42 in hexadecimal

# Decode the base64 string
decoded_bytes = base64.b64decode(encoded_string)

# XOR decryption function
def xor_decrypt(data, key):
    return bytes([b ^ key for b in data])

# Decrypt the data using XOR with the hex key
decrypted_data = xor_decrypt(decoded_bytes, hex_key)

with open("dec.kdbx", "wb") as file:
    file.write(decrypted_data)

NEXT step is to extract the hash file to crack and find the first character to get the full password.
keepass2john dec.kdbx >>dbhhash.txt
└──╼ $cat dbhhash.txt
$keepass$*2*60000*0*3909e7d4ae5b6c***********

Final Steps:
Use Hashcat to brute-force missing characters of the password.
──╼ $sudo hashcat -m 13400 -a 3 dbhhash.txt ?a"thepassword"

Result:
Once complete, the password opens the reconstructed database.


