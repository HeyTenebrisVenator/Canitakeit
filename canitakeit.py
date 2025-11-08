#!/usr/bin/env python3
import dns.resolver
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from tabulate import tabulate
from colorama import Fore, Style, init

init(autoreset=True)

VULNERABLE_CNAME_FINGERPRINTS = {
    "elasticbeanstalk.com": "AWS Elastic Beanstalk",
    "s3.amazonaws.com": "AWS S3",
    "agilecrm.com": "Agile CRM",
    "airee.ru": "Airee.ru",
    "animaapp.io": "Anima",
    "bitbucket.io": "Bitbucket",
    "trydiscourse.com": "Discourse",
    "hatenablog.com": "Hatena Blog",
    "helpjuice.com": "Help Juice",
    "helpscoutdocs.com": "Help Scout",
    "helprace.com": "Helprace",
    "azurewebsites.net": "Azure App Service",
    "cloudapp.net": "Azure CloudApp",
    "azureedge.net": "Azure CDN",
    "azurecr.io": "Azure Container Registry",
    "ngrok.io": "Ngrok",
    "launchrock.com": "LaunchRock",
    "readme.io": "ReadMe.io",
    "readthedocs.io": "Read the Docs",
    "surge.sh": "Surge.sh",
    "s.strikinglydns.com": "Strikingly",
    "wordpress.com": "WordPress",
    "worksites.net": "Worksites",
    "uberflip.com": "Uberflip",
    "smartjobboard.com": "SmartJobBoard",
}

def check_cname(subdomain):
    try:
        answers = dns.resolver.resolve(subdomain, 'CNAME')
        for rdata in answers:
            cname = str(rdata.target).rstrip('.')
            for fingerprint, provider in VULNERABLE_CNAME_FINGERPRINTS.items():
                if fingerprint in cname:
                    return (
                        subdomain,
                        cname,
                        provider,
                        f"{Fore.YELLOW}⚠️ POSSIBLE TAKEOVER{Style.RESET_ALL}"
                    )
            return (subdomain, cname, "-", f"{Fore.GREEN}✅ Safe{Style.RESET_ALL}")
    except dns.resolver.NXDOMAIN:
        return (subdomain, "-", "-", f"{Fore.RED}❌ NXDOMAIN{Style.RESET_ALL}")
    except dns.resolver.NoAnswer:
        return (subdomain, "-", "-", f"{Fore.BLUE}ℹ️ No CNAME{Style.RESET_ALL}")
    except Exception as e:
        return (subdomain, "-", "-", f"{Fore.MAGENTA}Error: {e}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(
        description="Subdomain takeover CNAME checker (multi-threaded)"
    )
    parser.add_argument(
        "-i", "--input", required=True, help="Arquivo com lista de subdomínios"
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=20, help="Número de threads (default: 20)"
    )
    parser.add_argument(
        "-o", "--output", help="Arquivo de saída (opcional, formato .txt ou .csv)"
    )

    args = parser.parse_args()

    with open(args.input) as f:
        subdomains = [line.strip() for line in f if line.strip()]

    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_sub = {executor.submit(check_cname, sub): sub for sub in subdomains}
        for future in as_completed(future_to_sub):
            results.append(future.result())

    print(tabulate(results, headers=["Subdomain", "CNAME", "Provider", "Status"], tablefmt="grid"))

    if args.output:
        with open(args.output, "w") as f:
            for r in results:
                f.write(",".join(r) + "\n")
        print(f"\nResultados salvos em: {args.output}")

if __name__ == "__main__":
    main()
