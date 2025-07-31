# RTF DDE SCT Exploit (Educational PoC)

This repository contains an educational proof-of-concept RTF exploit that abuses the DDEAUTO field to execute a remote payload via regsvr32 and .sct scripting.

## ⚠️ Disclaimer

This code is provided **strictly for educational and ethical security research purposes**.  
Do not use in any unauthorized or malicious way.  
The author assumes no responsibility for misuse or damage.

## 💥 How It Works

- RTF embeds a DDEAUTO field calling cmd.exe
- Executes regsvr32 with a remote `.sct` file
- `.sct` triggers a PowerShell download-and-execute payload

## 🚫 Not Included

- No real malware or C2
- No reverse shell payloads
- No encoding, no bypass tricks

## 🔗 References

- [DDE abuse explained](https://www.fireeye.com/blog/threat-research/2017/11/deep-dive-into-dde-exploit.html)
- [MITRE T1217: Regsvr32](https://attack.mitre.org/techniques/T1217/)
