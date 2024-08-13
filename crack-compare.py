import re
import argparse
from collections import defaultdict
from colorama import Fore, Style

# Function to validate and parse cracked hashes
def parse_cracked_hashes_simple(file_content):
    hashes = []
    invalid_hashes = []
    for line in file_content.splitlines():
        line = line.strip()
        if line:
            parts = re.split(r'[:, ]+', line)
            if len(parts[0]) == 32 and re.match(r'^[0-9a-fA-F]+$', parts[0]):
                lm_hash = parts[0]  # This is the LM hash
                nt_hash = parts[1] if len(parts) > 1 and len(parts[1]) == 32 else None  # This is the NT hash
                password = parts[2] if len(parts) > 2 else None
                hashes.append((lm_hash, nt_hash, password))
            else:
                invalid_hashes.append(line)
    
    if invalid_hashes:
        print(f"{Fore.RED}Error: Detected {len(invalid_hashes)} invalid LM hashes.{Style.RESET_ALL}")
        print(f"Example of invalid entry: {invalid_hashes[0]}")
        print("Please review the input file and correct any errors.")
        exit(1)
    
    return hashes

# Function to find and count matches in NTDS dump
def count_matches(hashes, ntds_content):
    count_dict = defaultdict(list)
    ntds_lines = ntds_content.splitlines()
    
    for lm_hash, nt_hash, _ in hashes:
        for line in ntds_lines:
            if lm_hash and lm_hash in line:
                count_dict[lm_hash].append(line)
            if nt_hash and nt_hash in line:
                count_dict[nt_hash].append(line)
    
    return count_dict

# Function to check if a username contains admin-like patterns and highlight it in bold red
def highlight_admin_users(username, domain_admins):
    patterns = [r".*\.adm.*", r".*-adm.*", r".*\.admin.*", r".*-admin.*", r"adm\..*", r"admin\..*"]
    for pattern in patterns:
        if re.match(pattern, username, re.IGNORECASE):
            highlight = f"{Fore.RED}{Style.BRIGHT}{username}{Style.RESET_ALL}"
            if username in domain_admins:
                highlight += f" {Fore.YELLOW}{Style.BRIGHT}(DOMAIN ADMIN){Style.RESET_ALL}"
            return highlight
    if username in domain_admins:
        return f"{Fore.RED}{Style.BRIGHT}{username} {Fore.YELLOW}(DOMAIN ADMIN){Style.RESET_ALL}"
    return username

# Function to extract the username from a given NTDS line
def extract_username(line):
    if "\\" in line:
        return line.split("\\")[1].split(":")[0]
    elif ":" in line:
        return line.split(":")[0]
    else:
        return line

# Function to display results and optionally write to a file
def display_results(count_dict, domain_admins, hashes, output_file=None, debug=False):
    results = []
    detailed_results = []
    admin_only_results = []
    unique_users = set()
    possible_admin_count = 0
    total_shared_hashes = 0
    domain_admin_count = 0
    sorted_hashes = sorted(count_dict.items(), key=lambda x: len(x[1]), reverse=True)
    
    # Collect data and prepare output
    for lm_hash, users in sorted_hashes:
        user_count = len(users)
        for user in users:
            user_name = extract_username(user)
            if user_name in domain_admins or re.search(r".*adm.*|.*admin.*", user_name, re.IGNORECASE):
                highlighted_user = highlight_admin_users(user_name, domain_admins)
                if highlighted_user != user_name:
                    possible_admin_count += 1
                if user_name in domain_admins:
                    domain_admin_count += 1
                password = next((pwd for h, n, pwd in hashes if h == lm_hash), None)
                if user_count == 1:
                    admin_only_results.append(f"{highlighted_user} (LM Hash: {lm_hash})" + (f" Cleartext: {password}" if password else ""))
                break  # No need to check other users for this hash
                
        if user_count > 1:
            unique_users.update(users)
            total_shared_hashes += 1
            prefix = f"{Fore.LIGHTYELLOW_EX}**{Style.RESET_ALL} " if user_count > 2 else "   "
            highlighted_hash = lm_hash[:-6] + f"{Fore.LIGHTYELLOW_EX}{lm_hash[-6:]}{Style.RESET_ALL}"
            result_line = f"{prefix}{highlighted_hash}: {user_count} users"
            results.append(result_line)
            
            detailed_results.append(f"{highlighted_hash}:")
            for user in users:
                user_name = extract_username(user)
                highlighted_user = highlight_admin_users(user_name, domain_admins)
                password = next((pwd for h, n, pwd in hashes if h == lm_hash), None)
                detailed_results.append(f"    {highlighted_user}" + (f" Cleartext: {password}" if password else ""))

    # Calculate padding for right-justification
    total_users = len(unique_users)
    max_digits = max(len(str(total_users)), len(str(possible_admin_count)), len(str(total_shared_hashes)), len(str(domain_admin_count)))
    padding = max_digits + 1  # +1 for a space between the colon and the value

    total_users_line = f"Total Unique Users Across Shared Hashes: {Fore.GREEN}{str(total_users).rjust(padding)}{Style.RESET_ALL}"
    separator_line = "-" * len(total_users_line)
    
    # Align the admin stats and total shared hashes with the colon in the total_users_line
    colon_position = len("Total Unique Users Across Shared Hashes:")  # Find the position of the colon
    domain_admins_line = f"{' ' * (colon_position - len('Domain Admins Cracked:'))}Domain Admins Cracked: {Fore.YELLOW if domain_admin_count > 0 else Fore.RED}{Style.BRIGHT if domain_admin_count > 0 else ''}{str(domain_admin_count).rjust(padding)}{Style.RESET_ALL}"
    admin_stats_line = f"{' ' * (colon_position - len('Possible Admin Accounts:'))}Possible Admin Accounts: {Fore.RED}{str(possible_admin_count).rjust(padding)}{Style.RESET_ALL}"
    shared_hashes_line = f"{' ' * (colon_position - len('Total Shared Hashes:'))}Total Shared Hashes: {str(total_shared_hashes).rjust(padding)}"
    
    if debug:
        print("Parsed Hashes:", hashes)
        print("NTDS Lines:", ntds_lines)
        print("Count Dict:", dict(count_dict))
        print("Debugging user parsing:")
        for hash_val, users in sorted_hashes:
            for user in users:
                print(f"Raw user data: {user}")
                user_name = extract_username(user)
                print(f"Parsed user name: {user_name}")

    # Regular output
    if results:
        if debug:
            print(separator_line)
            print(total_users_line)
            print(domain_admins_line)
            print(admin_stats_line)
            print(shared_hashes_line)
            print(separator_line + "\n")
            if admin_only_results:
                print("Admin or Domain Admin Cracked Hashes (Single User):")
                for line in admin_only_results:
                    print(line)
                print()
            for line in results:
                print(line)
            print("\nDetailed List of Users per Hash:")
            for line in detailed_results:
                print(line)
        else:
            if output_file:
                print(f"{total_users} users found across multiple shared hashes")
            else:
                print(separator_line)
                print(total_users_line)
                print(domain_admins_line)
                print(admin_stats_line)
                print(shared_hashes_line)
                print(separator_line + "\n")
                if admin_only_results:
                    print("Admin or Domain Admin Cracked Hashes (Single User):")
                    for line in admin_only_results:
                        print(line)
                    print()
                for line in results:
                    print(line)
                print("\nDetailed List of Users per Hash:")
                for line in detailed_results:
                    print(line)
    else:
        if output_file:
            print("No matches found. No output file will be created.")
        else:
            print("No matches found.")

    # Optionally write results to a file
    if output_file and results:
        with open(output_file, 'w') as f:
            if debug:
                f.write(separator_line + "\n")
                f.write(total_users_line + "\n")
                f.write(domain_admins_line + "\n")
                f.write(admin_stats_line + "\n")
                f.write(shared_hashes_line + "\n")
                f.write(separator_line + "\n\n")
                if admin_only_results:
                    f.write("Admin or Domain Admin Cracked Hashes (Single User):\n")
                    for line in admin_only_results:
                        f.write(line + "\n")
                    f.write("\n")
                f.write("Parsed Hashes:\n")
                f.write(str(hashes) + "\n")
                f.write("NTDS Lines:\n")
                f.write("\n".join(ntds_lines) + "\n")
                f.write("Count Dict:\n")
                f.write(str(dict(count_dict)) + "\n\n")
            f.write(separator_line + "\n")
            f.write(total_users_line + "\n")
            f.write(domain_admins_line + "\n")
            f.write(admin_stats_line + "\n")
            f.write(shared_hashes_line + "\n")
            f.write(separator_line + "\n\n")
            if admin_only_results:
                f.write("Admin or Domain Admin Cracked Hashes (Single User):\n")
                for line in admin_only_results:
                    f.write(line + "\n")
                f.write("\n")
            f.write("\n".join(results) + "\n\n")
            f.write("Detailed List of Users per Hash:\n")
            f.write("\n".join(detailed_results))

# Main function with argument parsing
def main():
    parser = argparse.ArgumentParser(
        description="Analyze NTDS dump and cracked hashes, highlighting possible admin accounts and domain admin accounts.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-n", "--ntds", required=True, help="NTDS dump file path")
    parser.add_argument("-c", "--cracked", required=True, help="Cracked hashes file path")
    parser.add_argument("-DA", "--domain-admins", help="File path for Domain Admins list")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")

    args = parser.parse_args()

    # Load Domain Admins list if provided
    domain_admins = set()
    if args.domain_admins:
        with open(args.domain_admins, 'r') as da_file:
            domain_admins = set([line.strip() for line in da_file.readlines()])
    
    # Read files
    with open(args.ntds, 'r') as ntds_file:
        ntds_file_content = ntds_file.read()
    
    with open(args.cracked, 'r') as cracked_hashes_file:
        cracked_hashes_file_content = cracked_hashes_file.read()
    
    # Step 1: Parse cracked hashes with validation
    hashes = parse_cracked_hashes_simple(cracked_hashes_file_content)
    
    # Step 2: Count matches in NTDS dump
    count_dict = count_matches(hashes, ntds_file_content)
    
    # Step 3: Display results or save to file
    display_results(count_dict, domain_admins, hashes, args.output, args.debug)

# Run the main function if this script is executed
if __name__ == "__main__":
    main()
