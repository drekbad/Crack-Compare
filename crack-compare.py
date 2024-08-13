import re
from collections import defaultdict
import argparse
from colorama import Fore, Style

# Function to parse cracked hashes directly from a simple list
def parse_cracked_hashes_simple(file_content):
    hashes = []
    for line in file_content.splitlines():
        line = line.strip()
        if line:
            # If the line contains a colon, it could be NT:LM or LM:plaintext
            if ':' in line:
                parts = line.split(':')
                lm_hash = parts[0].strip() if len(parts) > 0 else None
                nt_hash = parts[1].strip() if len(parts) > 1 else None
                hashes.append((lm_hash, nt_hash))
            else:
                # Assume it's a single hash, could be LM or NT
                hashes.append((line, None))
    return hashes

# Function to find and count matches in NTDS dump
def count_matches(hashes, ntds_content):
    count_dict = defaultdict(list)
    ntds_lines = ntds_content.splitlines()
    
    for lm_hash, nt_hash in hashes:
        for line in ntds_lines:
            if lm_hash and lm_hash in line:
                count_dict[lm_hash].append(line)
            if nt_hash and nt_hash in line:
                count_dict[nt_hash].append(line)
    
    return count_dict

# Function to check if a username contains admin-like patterns and highlight it in bold red
def highlight_admin_users(username):
    patterns = [r".*\.adm.*", r".*-adm.*", r".*\.admin.*", r".*-admin.*", r"adm\..*", r"admin\..*"]
    for pattern in patterns:
        if re.match(pattern, username, re.IGNORECASE):
            return f"{Fore.RED}{Style.BRIGHT}{username}{Style.RESET_ALL}"
    return username

# Function to display results and optionally write to a file
def display_results(count_dict, output_file=None, debug=False):
    results = []
    detailed_results = []
    unique_users = set()
    possible_admin_count = 0
    sorted_hashes = sorted(count_dict.items(), key=lambda x: len(x[1]), reverse=True)
    
    # Collect data and prepare output
    for hash_val, users in sorted_hashes:
        user_count = len(users)
        if user_count > 1:
            unique_users.update(users)
            prefix = f"{Fore.LIGHTYELLOW_EX}**{Style.RESET_ALL} " if user_count > 2 else "   "
            highlighted_hash = hash_val[:-6] + f"{Fore.LIGHTYELLOW_EX}{hash_val[-6:]}{Style.RESET_ALL}"
            result_line = f"{prefix}{highlighted_hash}: {user_count} users"
            results.append(result_line)
            
            detailed_results.append(f"{highlighted_hash}:")
            for user in users:
                user_name = user.split("\\")[1].split(":")[0] if "\\" in user and ":" in user else user
                highlighted_user = highlight_admin_users(user_name)
                if highlighted_user != user_name:  # Check if it was highlighted
                    possible_admin_count += 1
                detailed_results.append(f"    {highlighted_user}")

    # Display total unique users involved
    total_users = len(unique_users)
    total_users_line = f"Total Unique Users Across Shared Hashes: {Fore.GREEN}{total_users}{Style.RESET_ALL}"
    separator_line = "-" * len(total_users_line)
    
    # Admin account statistics
    admin_stats_line = f"    Possible Admin Accounts: {Fore.RED}{Style.BRIGHT}{possible_admin_count}{Style.RESET_ALL}"
    
    if debug:
        print("Parsed Hashes:", hashes)
        print("NTDS Lines:", ntds_lines)
        print("Count Dict:", dict(count_dict))
        print("Debugging user parsing:")
        for hash_val, users in sorted_hashes:
            for user in users:
                print(f"Raw user data: {user}")
                user_name = user.split("\\")[1].split(":")[0] if "\\" in user and ":" in user else user
                print(f"Parsed user name: {user_name}")

    # Regular output
    if results:
        if debug:
            print(separator_line)
            print(total_users_line)
            print(separator_line)
            print(admin_stats_line + "\n")
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
                print(separator_line)
                print(admin_stats_line + "\n")
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
                f.write(separator_line + "\n\n")
                f.write(admin_stats_line + "\n\n")
                f.write("Parsed Hashes:\n")
                f.write(str(hashes) + "\n")
                f.write("NTDS Lines:\n")
                f.write("\n".join(ntds_lines) + "\n")
                f.write("Count Dict:\n")
                f.write(str(dict(count_dict)) + "\n\n")
            f.write(separator_line + "\n")
            f.write(total_users_line + "\n")
            f.write(separator_line + "\n\n")
            f.write(admin_stats_line + "\n\n")
            f.write("\n".join(results) + "\n\n")
            f.write("Detailed List of Users per Hash:\n")
            f.write("\n".join(detailed_results))

# Main function with argument parsing
def main():
    parser = argparse.ArgumentParser(description="Parse NTDS dump and cracked hashes.")
    parser.add_argument("-n", "--ntds", required=True, help="NTDS dump file path")
    parser.add_argument("-c", "--cracked", required=True, help="Cracked hashes file path")
    parser.add_argument("-o", "--output", help="Output file path to save the results")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")

    args = parser.parse_args()
    
    # Read files
    with open(args.ntds, 'r') as ntds_file:
        ntds_file_content = ntds_file.read()
    
    with open(args.cracked, 'r') as cracked_hashes_file:
        cracked_hashes_file_content = cracked_hashes_file.read()
    
    # Step 1: Parse cracked hashes with the simpler parser
    hashes = parse_cracked_hashes_simple(cracked_hashes_file_content)
    
    # Step 2: Count matches in NTDS dump
    count_dict = count_matches(hashes, ntds_file_content)
    
    # Step 3: Display results or save to file
    display_results(count_dict, args.output, args.debug)

# Run the main function if this script is executed
if __name__ == "__main__":
    main()
