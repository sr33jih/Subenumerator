import os
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
import datetime

TOOLS = {
    "subfinder": lambda domain: f"subfinder -d {domain} -all -silent",
    "sublist3r": lambda domain: f"python3 Sublist3r/sublist3r.py -d {domain} -o -",
    "assetfinder": lambda domain: f"assetfinder --subs-only {domain}",
    "chaos": lambda domain: f"chaos -key $CHAOS_API_KEY -d {domain}",
    "findomain": lambda domain: f"findomain -t {domain} -q",
    "crtsh": lambda domain: f'curl -s "https://crt.sh/?q=%25.{domain}&output=json"'
}

def run_command(command):
    try:
        return subprocess.check_output(command, shell=True, stderr=subprocess.DEVNULL, text=True)
    except subprocess.CalledProcessError:
        return ""

def parse_crtsh(domain):
    import json
    from urllib.request import urlopen
    try:
        with urlopen(f"https://crt.sh/?q=%25.{domain}&output=json") as response:
            data = json.load(response)
            return "\n".join(set(entry["name_value"] for entry in data))
    except:
        return ""

def enumerate_subdomains(domain, output_dir):
    all_subs = set()
    for tool, cmd_func in TOOLS.items():
        output = ""
        if tool == "crtsh":
            output = parse_crtsh(domain)
        else:
            output = run_command(cmd_func(domain))
        file_path = os.path.join(output_dir, f"{tool}_{domain}.txt")
        with open(file_path, "w") as f:
            f.write(output)
        all_subs.update(line.strip() for line in output.splitlines() if domain in line)
    return all_subs

def filter_live_subdomains(subdomains, output_dir):
    all_path = os.path.join(output_dir, "all.txt")
    live_path = os.path.join(output_dir, "live.txt")
    with open(all_path, "w") as f:
        f.write("\n".join(sorted(subdomains)))
    subprocess.run(f"cat {all_path} | httpx -silent -threads 50 -status-code -no-color -o {live_path}", shell=True)

def process_domain(domain, base_output):
    output_dir = os.path.join(base_output, domain)
    os.makedirs(output_dir, exist_ok=True)
    all_subs = enumerate_subdomains(domain, output_dir)
    filter_live_subdomains(all_subs, output_dir)

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Subenumerator: Multi-tool Subdomain Enumerator")
    parser.add_argument("-d", "--domain", help="Target domain")
    parser.add_argument("-l", "--list", help="File with list of target domains")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of concurrent threads")
    args = parser.parse_args()

    base_output = os.path.join(os.getcwd(), f"Subenum_Results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}")
    os.makedirs(base_output, exist_ok=True)

    targets = []
    if args.domain:
        targets.append(args.domain)
    elif args.list:
        with open(args.list) as f:
            targets = [line.strip() for line in f if line.strip()]

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        list(tqdm(executor.map(lambda d: process_domain(d, base_output), targets), total=len(targets)))

if __name__ == "__main__":
    main()
