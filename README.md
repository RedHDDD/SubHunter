<p align="center">   <img src="SubHunter.png" alt="SubHunter" width="480"> </p>

# SubHunter

SubHunter is a Python tool that finds subdomains using crt.sh, DNS lookups, and virtual host enumeration.

## Installation

Requires Python 3.10 or newer.
```bash
git clone https://github.com/RedHDDD/SubHunter.git
cd SubHunter
pip install -r requirements.txt
```

## Usage

Run the tool without arguments for interactive mode.
```
python SubHunter.py
```

Run all modules:
```
python SubHunter.py -u example.com -w words.txt
```

CRT only (no wordlist needed):
```
python SubHunter.py -u example.com -c
```

DNS only:
```
python SubHunter.py -u example.com -w words.txt -d
```

VHost only:
```
python SubHunter.py -u example.com -w words.txt -v
```

Run CRT and DNS together:
```
python SubHunter.py -u example.com -w words.txt -c -d
```

Save results to a file:
```
python SubHunter.py -u example.com -w words.txt -o results.txt
```

Custom User-Agent:
```
python SubHunter.py -u example.com -c --user-agent "Mozilla/5.0"
```

## Author

[GitHub](https://github.com/RedHDDD) | [LinkedIn](https://www.linkedin.com/in/saleh-almajed1/)
