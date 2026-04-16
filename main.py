"""
IAMGuard - AWS IAM Security Scanner
Identifies misconfigurations and security risks in AWS IAM
Built by Marshall Roberson
"""

from iamguard.scanner import IAMScanner
from colorama import init, Fore, Style

init(autoreset=True)

def print_banner():
    print(Fore.CYAN + """
    ██╗ █████╗ ███╗   ███╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
    ██║██╔══██╗████╗ ████║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
    ██║███████║██╔████╔██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
    ██║██╔══██║██║╚██╔╝██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
    ██║██║  ██║██║ ╚═╝ ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
    ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
    """ + Style.RESET_ALL)
    print(Fore.WHITE + "    AWS IAM Security Scanner v1.0")
    print(Fore.WHITE + "    Built by Marshall Roberson")
    print(Fore.WHITE + "    github.com/marshallroberson24-ux\n")

def print_summary(summary):
    print("\n" + "=" * 60)
    print(Fore.CYAN + "    SCAN SUMMARY")
    print("=" * 60)
    print(Fore.RED +    f"    Critical : {summary['CRITICAL']}")
    print(Fore.YELLOW + f"    High     : {summary['HIGH']}")
    print(Fore.BLUE +   f"    Medium   : {summary['MEDIUM']}")
    print(Fore.GREEN +  f"    Low      : {summary['LOW']}")
    print(Fore.WHITE +  f"    Total    : {summary['total']}")
    print("=" * 60 + "\n")

if __name__ == "__main__":
    print_banner()
    
    scanner = IAMScanner()
    scanner.run_all_checks()
    
    summary = scanner.get_summary()
    print_summary(summary)
    
    scanner.export_json()
    print(Fore.GREEN + "✅ Scan complete. Results saved to iamguard_results.json")