#!/usr/bin/env python3

import argparse
import csv
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver
from tabulate import tabulate
from colorama import Fore, Style, init


init(autoreset=True)


TAKEOVER_CNAME_FINGERPRINTS = {
    "elasticbeanstalk.com": "AWS Elastic Beanstalk",
    "s3.amazonaws.com": "AWS S3",
    "agilecrm.com": "Agile CRM",
    "airee.ru": "Airee",
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
    "readme.io": "ReadMe",
    "readthedocs.io": "Read the Docs",
    "surge.sh": "Surge",
    "s.strikinglydns.com": "Strikingly",
    "wordpress.com": "WordPress",
    "worksites.net": "Worksites",
    "uberflip.com": "Uberflip",
    "smartjobboard.com": "SmartJobBoard",
}


@dataclass
class CheckResult:
    subdomain: str
    cname: str
    provider: str
    status: str
    details: str = ""


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Multithreaded CNAME-based subdomain takeover checker"
    )

    parser.add_argument(
        "-i",
        "--input",
        required=True,
        help="Input file containing subdomains, one per line",
    )

    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=20,
        help="Number of worker threads",
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Optional output file. Supported formats: .txt or .csv",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="DNS query timeout in seconds",
    )

    parser.add_argument(
        "--lifetime",
        type=float,
        default=5.0,
        help="Maximum lifetime for each DNS resolution attempt",
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored terminal output",
    )

    return parser.parse_args()


def load_subdomains(input_file: str) -> list[str]:
    subdomains = []

    with open(input_file, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            subdomain = line.strip()

            if not subdomain or subdomain.startswith("#"):
                continue

            subdomains.append(subdomain)

    return list(dict.fromkeys(subdomains))


def build_resolver(timeout: float, lifetime: float) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = lifetime
    return resolver


def find_matching_provider(cname: str) -> tuple[str, str] | None:
    normalized_cname = cname.lower().rstrip(".")

    for fingerprint, provider in TAKEOVER_CNAME_FINGERPRINTS.items():
        if fingerprint.lower() in normalized_cname:
            return fingerprint, provider

    return None


def color_status(status: str, no_color: bool = False) -> str:
    if no_color:
        return status

    if status == "POSSIBLE_TAKEOVER":
        return f"{Fore.YELLOW}POSSIBLE TAKEOVER{Style.RESET_ALL}"

    if status == "SAFE":
        return f"{Fore.GREEN}SAFE{Style.RESET_ALL}"

    if status == "NXDOMAIN":
        return f"{Fore.RED}NXDOMAIN{Style.RESET_ALL}"

    if status == "NO_CNAME":
        return f"{Fore.BLUE}NO CNAME{Style.RESET_ALL}"

    return f"{Fore.MAGENTA}{status}{Style.RESET_ALL}"


def check_cname(
    subdomain: str,
    timeout: float,
    lifetime: float,
) -> CheckResult:
    resolver = build_resolver(timeout, lifetime)

    try:
        answers = resolver.resolve(subdomain, "CNAME")

        for record in answers:
            cname = str(record.target).rstrip(".")
            match = find_matching_provider(cname)

            if match:
                fingerprint, provider = match

                return CheckResult(
                    subdomain=subdomain,
                    cname=cname,
                    provider=provider,
                    status="POSSIBLE_TAKEOVER",
                    details=f"Matched CNAME fingerprint: {fingerprint}",
                )

            return CheckResult(
                subdomain=subdomain,
                cname=cname,
                provider="-",
                status="SAFE",
                details="CNAME found, but no known takeover fingerprint matched",
            )

        return CheckResult(
            subdomain=subdomain,
            cname="-",
            provider="-",
            status="NO_CNAME",
            details="No CNAME records returned",
        )

    except dns.resolver.NXDOMAIN:
        return CheckResult(
            subdomain=subdomain,
            cname="-",
            provider="-",
            status="NXDOMAIN",
            details="Domain does not exist",
        )

    except dns.resolver.NoAnswer:
        return CheckResult(
            subdomain=subdomain,
            cname="-",
            provider="-",
            status="NO_CNAME",
            details="No CNAME record found",
        )

    except dns.resolver.Timeout:
        return CheckResult(
            subdomain=subdomain,
            cname="-",
            provider="-",
            status="TIMEOUT",
            details="DNS query timed out",
        )

    except dns.resolver.NoNameservers:
        return CheckResult(
            subdomain=subdomain,
            cname="-",
            provider="-",
            status="NO_NAMESERVERS",
            details="No usable nameservers responded",
        )

    except Exception as error:
        return CheckResult(
            subdomain=subdomain,
            cname="-",
            provider="-",
            status="ERROR",
            details=str(error),
        )


def write_csv(results: list[CheckResult], output_file: str) -> None:
    with open(output_file, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["subdomain", "cname", "provider", "status", "details"])

        for result in results:
            writer.writerow([
                result.subdomain,
                result.cname,
                result.provider,
                result.status,
                result.details,
            ])


def write_txt(results: list[CheckResult], output_file: str) -> None:
    with open(output_file, "w", encoding="utf-8") as file:
        for result in results:
            file.write(
                f"{result.subdomain} | "
                f"CNAME: {result.cname} | "
                f"Provider: {result.provider} | "
                f"Status: {result.status} | "
                f"Details: {result.details}\n"
            )


def save_results(results: list[CheckResult], output_file: str) -> None:
    if output_file.lower().endswith(".csv"):
        write_csv(results, output_file)
    else:
        write_txt(results, output_file)


def print_results(results: list[CheckResult], no_color: bool = False) -> None:
    table = []

    for result in results:
        table.append([
            result.subdomain,
            result.cname,
            result.provider,
            color_status(result.status, no_color=no_color),
            result.details,
        ])

    print(
        tabulate(
            table,
            headers=["Subdomain", "CNAME", "Provider", "Status", "Details"],
            tablefmt="grid",
        )
    )


def run_checks(
    subdomains: list[str],
    threads: int,
    timeout: float,
    lifetime: float,
) -> list[CheckResult]:
    results = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(check_cname, subdomain, timeout, lifetime): subdomain
            for subdomain in subdomains
        }

        for future in as_completed(futures):
            results.append(future.result())

    return sorted(results, key=lambda item: item.subdomain)


def main() -> None:
    args = parse_arguments()

    subdomains = load_subdomains(args.input)

    if not subdomains:
        print("[!] No valid subdomains found in input file.")
        return

    print(f"[*] Loaded {len(subdomains)} unique subdomains")
    print(f"[*] Starting DNS checks with {args.threads} workers")

    results = run_checks(
        subdomains=subdomains,
        threads=args.threads,
        timeout=args.timeout,
        lifetime=args.lifetime,
    )

    print_results(results, no_color=args.no_color)

    possible_takeovers = [
        result for result in results
        if result.status == "POSSIBLE_TAKEOVER"
    ]

    print()
    print("[+] Scan completed")
    print(f"[+] Total checked: {len(results)}")
    print(f"[+] Possible takeovers: {len(possible_takeovers)}")

    if args.output:
        save_results(results, args.output)
        print(f"[+] Results saved to: {args.output}")


if __name__ == "__main__":
    main()
