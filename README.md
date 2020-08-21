# PennyScythe.py #

**Author  :**  Mike Gualtieri  
**Blog    :**  https://www.mike-gualtieri.com  
**Twitter :**  https://twitter.com/mlgualtieri  
**GitHub  :**  https://github.com/mlgualtieri/PennyScythe

## Intro ##
PennyScythe.py is a Python3 script that ingests and runs adversarial emulation plans from SCYTHE's Community Threats Repository.  Its goal is to aid in Purple Teaming exercises.  Its functionality is not limited to SCYTHE's Community Threats, and will support any modules developed with similar syntax.

https://github.com/scythe-io/community-threats
 
Many of SCYTHE's Community Threats work with this script.  Support status is indicated for each module with --list.


## Usage ##
```
Usage: python[.exe] PennyScythe.py -t <threat> -r [-u <url>] [-s 5] [-c] [-d] [-h] [-l] [-r]
```
```
Main options:
  -c, --compat            Test the specified --threat or --url for compatibility
  -d, --debug             Turn on debug options likely only useful to the author
                          of this script
  -h, --help
  -l, --list              List all available --threat modules
  -r, --run               Run the specified --threat or --url
  -s, --sleep  <seconds>  Sleep time in seconds between steps of the executed
                          --threat or --url; default is 5
  -t, --threat <threat>   Specify a threat to test --compat or --run;
                          (to view all available threat modules use --list)
  -u, --url    <url>      Supply a URL to a prepared threat plan
```

## Examples ##
List all available threats:
```
python3 PennyScythe.py --list
```
Run the EvilCorp/EvilCorp-WastedLocker threat:
```
python3 PennyScythe.py --threat EvilCorp/EvilCorp-WastedLocker --run
```
Run the EvilCorp/EvilCorp-WastedLocker threat pausing for 1 second between steps (default sleep is 5 seconds):
```
python3 PennyScythe.py --threat EvilCorp/EvilCorp-WastedLocker --run --sleep 1
```
Run the threat from a specified url:
```
python3 PennyScythe.py --run --url https://raw.githubusercontent.com/scythe-io/community-threats/master/EvilCorp/WastedLocker_scythe_threat.json
```


## DISCLAIMER: ##
I don't work for SCYTHE and this project is in no way associated with or endorsed by scythe.io.  Use at your own risk!  Unicorns welcome!
