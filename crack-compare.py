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

# Function to identify the type of input hashes
def identify_hash_type(hashes):
    lm_only = all(h[0] and not h[1] for h in hashes)
    nt_only = all(not h[0] and h[1] for h in hashes)
    mixed = not (lm_only or nt_only)
    
    if mixed:
        return "mixed"
    elif lm_only:
        return "lm_only"
    elif nt_only:
        return "nt_only"
    else:
        return "unknown"

# Function to find and count matches in NTDS dump
def count_matches_debug(hashes, ntds_content):
    count_dict = defaultdict(int)
    ntds_lines = ntds_content.splitlines()
    
    for lm_hash, nt_hash in hashes:
        if lm_hash:
            for line in ntds_lines:
                if lm_hash in line:
                    count_dict[lm_hash] += 1
        if nt_hash:
            for line in ntds_lines:
                if nt_hash in line:
                    count_dict[nt_hash] += 1
    
    return count_dict

# Function to display results and optionally write to a file
def display_results(count_dict, output_file=None):
    sorted_hashes = sorted(count_dict.items(), key=lambda x: x[1], reverse=True)
    
    # Determine top N for highlighting
    top_n = 3 if len(sorted_hashes) > 5 else len(sorted_hashes)
    top_n = 5 if len(sorted_hashes) > 10 else top_n
    
    results = []
    for idx, (hash_val, count) in enumerate(sorted_hashes):
        if idx < top_n:
            result_line = f"** {hash_val}: {count} users **"
        else:
            result_line = f"{hash_val}: {count} users"
        results.append(result_line)
    
    # Print results to screen
    for line in results:
        print(line)
    
    # Optionally write results to a file
    if output_file:
        with open(output_file, 'w') as f:
            f.write("\n".join(results))

# Main function with argument parsing
def main():
    parser = argparse.ArgumentParser(description="Parse NTDS dump and cracked hashes.")
    parser.add_argument("-n", "--ntds", required=True, help="NTDS dump file path")
    parser.add_argument("-c", "--cracked", required=True, help="Cracked hashes file path")
    parser.add_argument("-o", "--output", help="Output file path to save the results")

    args = parser.parse_args()
    
    # Read files
    with open(args.ntds, 'r') as ntds_file:
        ntds_file_content = ntds_file.read()
    
    with open(args.cracked, 'r') as cracked_hashes_file:
        cracked_hashes_file_content = cracked_hashes_file.read()
    
    # Step 1: Parse cracked hashes with the simpler parser
    hashes = parse_cracked_hashes_simple(cracked_hashes_file_content)
    
    # Step 3: Count matches in NTDS dump
    count_dict = count_matches_debug(hashes, ntds_file_content)
    
    # Step 4: Display results or save to file
    display_results(count_dict, args.output)

# Run the main function if this script is executed
if __name__ == "__main__":
    main()
