# Crack-Compare
Compare cracked hashes to that of dumped NTDS to identify password reuse or other patterns

## 🎯 Purpose

Compare an NTDS dump with a list of cracked NTLMs, and call attention to:
 - passworod reuse
 - possible admin accounts whose hashes were cracked
 - Domain Admins whose hashes were cracked

## 🛠 Usage

Run `crack-compare` with required NTDS and CRACKED flags, along with optional DOMAIN_ADMINS input:

```bash
python3 crack-compare.py -n <NTDS dump file> -c <Cracked NTLMs file> [-DA <list of DA users file>]
```

### Options at your disposal:

-n, --ntds: NTDS dump file path\
-c, --cracked: Cracked hashes file path\
-o, --output: Output file path to save the results\
-DA, --domain-admins: File path for Domain Admins list\
--debug: Enable debug mode\

### ⚓ Considerations
- Hashes displayed in the output primarily indicate where more than one user was associated with a given hash, except where related to a possible admin or confiremd DA
- NTDS file must be in the format:  `domain\Username:SID:NT:LM:::` where 'domain' is optional. This may be expanded for flexibility in the future as needed.
