import re
from collections import defaultdict
import argparse

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
        if lm_hash:
            for line in ntds_lines:
                if lm_hash in line:
                    count_dict[lm_hash].append(line)
        if nt_hash:
            for line in ntds_lines:
                if nt_hash in line:
                    count_dict[nt_hash].append(line)
    
    return count_dict

# Function to display results and optionally write to a file
def display_results(count_dict, output_file=None, debug=False):
    results = []
    sorted_hashes = sorted(count_dict.items(), key=lambda x: len(x[1]), reverse=True)
    
    for hash_val, users in sorted_hashes:
        user_count = len(users)
        if user_count > 1:
            prefix = "** " if user_count > 2 else ""
            result_line = f"{prefix}{hash_val}: {user_count} users"
            user_list = ", ".join([user.split("\\")[1].split(":")[0] for user in users])
            results.append(result_line)
            results.append(f"    {user_list}")
    
    # Debug output
    if debug:
        print("Parsed Hashes:", hashes)
        print("NTDS Lines:", ntds_lines)
        print("Count Dict:", dict(count_dict))
    
    # Regular output
    if results:
        if debug:
            for line in results:
                print(line)
        else:
            if output_file:
                print(f"{len(results)} hashes found for more than one user")
            else:
                for line in results:
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
                f.write("Parsed Hashes:\n")
                f.write(str(hashes) + "\n")
                f.write("NTDS Lines:\n")
                f.write("\n".join(ntds_lines) + "\n")
                f.write("Count Dict:\n")
                f.write(str(dict(count_dict)) + "\n\n")
            f.write("\n".join(results))

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
