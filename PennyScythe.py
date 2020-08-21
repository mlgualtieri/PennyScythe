#!/usr/bin/env python3
#
# PennyScythe.py is a Python3 script that ingests and runs adversarial emulation
# plans from SCYTHE's Community Threats Repository.  Its goal is to aid in 
# Purple Teaming exercises.  Its functionality is not limited to SCYTHE's
# Community Threats, and will support any modules developed with similar syntax.
#
# https://github.com/scythe-io/community-threats
# 
# Many of SCYTHE's Community Threats work with this script.  Support status is
# indicated for each module with --list.
#
# Usage: python[.exe] PennyScythe.py -t EvilCorp/EvilCorp-WastedLocker -r
#
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#
# DISCLAIMER: I don't work for SCYTHE and this project is in no way associated 
# with or endorsed by scythe.io.  Use at your own risk!  Unicorns welcome!
#
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#
# Author  : Mike Gualtieri
# Blog    : https://www.mike-gualtieri.com
# Twitter : https://twitter.com/mlgualtieri
# GitHub  : https://github.com/mlgualtieri/PennyScythe
#

import os, time, datetime, sys, urllib.request, json, shutil, textwrap, getopt


# APT19/APT19                       (partial support - no printsreen)
# APT33/APT33                       (not supported)
# Buhtrap/Buhtrap-DNS               (not supported)
# Buhtrap/Buhtrap-HTTPS             (not supported)
# CozyBear/CozyBear-Step1           (supported)
# CozyBear/CozyBear-Step2           (partial support - no uploader, time delay)
# DeepPanda/Deep_Panda_Desrubi      (supported)
# Orangeworm/Orangeworm             (supported)
# Ransomware/Ransomware_Example     (supported)
# EvilCorp/EvilCorp-WastedLocker    (supported)

threats = {
    "APT19/APT19": {
        "display_name": "APT19 for #ThreatThursday",
        "description": "APT19",
        "url": "https://raw.githubusercontent.com/scythe-io/community-threats/master/APT19/APT19_scythe_threat.json",
        "support": "Partial Support"
    },
    "APT33/APT33": {
        "display_name": "APT33",
        "description": "APT33 is a suspected Iranian threat group that has carried out operations since at least 2013.",
        "url": "https://raw.githubusercontent.com/scythe-io/community-threats/master/APT33/APT33_scythe_threat.json",
        "support": "Not Supported"
    },
    "Buhtrap/Buhtrap-DNS": {
        "display_name": "Buhtrap-DNS",
        "description": "Long-haul C2 over DNS for the persistence portion of Buhtrap Adversary Emulation",
        "url": "https://raw.githubusercontent.com/scythe-io/community-threats/master/Buhtrap/Buhtrap-DNS_scythe_threat.json",
        "support": "Not Supported"
    },
    "Buhtrap/Buhtrap-HTTPS": {
        "display_name": "Buhtrap-HTTPS",
        "description": "Short-haul C2 over HTTPS for the collection portion of Buhtrap Adversary Emulation",
        "url": "https://raw.githubusercontent.com/scythe-io/community-threats/master/Buhtrap/Buhtrap-HTTPS_scythe_threat.json",
        "support": "Not Supported"
    },
    "CozyBear/CozyBear-Step1": {
        "display_name": "CozyBear-Step1",
        "description": "Cozy Bear Step 1 of the MITRE ATT&CK Evaluations Adversary Emulation Plan",
        "url": "https://raw.githubusercontent.com/scythe-io/community-threats/master/CozyBear/CozyBear-Step1_scythe_threat.json",
        "support": "Supported"
    },
    "CozyBear/CozyBear-Step2": {
        "display_name": "CozyBear-Step2",
        "description": "Cozy Bear Step 2 of the MITRE ATT&CK Evaluations Adversary Emulation Plan",
        "url": "https://raw.githubusercontent.com/scythe-io/community-threats/master/CozyBear/CozyBear-Step2_scythe_threat.json",
        "support": "Partial Support"
    },
    "DeepPanda/Deep_Panda_Desrubi": {
        "display_name": "Deep Panda Desrubi",
        "description": "Linux Variant of Desrubi",
        "url": "https://raw.githubusercontent.com/scythe-io/community-threats/master/DeepPanda/Deep_Panda_Desrubi_scythe_threat.json",
        "support": "Supported"
    },
    "EvilCorp/EvilCorp-WastedLocker": {
        "display_name": "WastedLocker",
        "description": "WastedLocker is the ransomware that was used by EvilCorp in the July 2020 attack against Garmin.",
        "url": "https://raw.githubusercontent.com/scythe-io/community-threats/master/EvilCorp/WastedLocker_scythe_threat.json",
        "support": "Supported"
    },
    "Orangeworm/Orangeworm": {
        "display_name": "Orangeworm",
        "description": "Orangeworm is a group that has targeted organizations in the healthcare sector in the United States, Europe, and Asia since at least 2015.",
        "url": "https://raw.githubusercontent.com/scythe-io/community-threats/master/Orangeworm/Orangeworm_scythe_threat.json",
        "support": "Supported"
    },
    "Ransomware/Ransomware_Example": {
        "display_name": "Ransomware Example",
        "description": "This Threat Template provides an example ransomware attack, but instead of using actual user data, it creates a directory with files specifically for the purpose of encrypting them. It then downloads a ransom note from the public internet.",
        "url": "https://raw.githubusercontent.com/scythe-io/community-threats/master/Ransomware/Ransomware_Example_scythe_threat.json",
        "support": "Supported"
    }
}



def listThreats():
    print('')
    print("Available Modules:")
    for threat in threats:
        print("\n  [*] ", threat, sep='')
        print("\tName        :", threats[threat]['display_name'])
        print("\tStatus      :", threats[threat]['support'])

        # Format/output description
        desc_out = "Description : " + threats[threat]['description']
        desc_wrapper = textwrap.TextWrapper(width=80, initial_indent=' ' * 8, subsequent_indent=' ' * 8) 
        desc_out = desc_wrapper.fill(text=desc_out) 
        print(desc_out)

    sys.exit()



def outputTimestamp():
    print("         > Timestamp: [{:%Y-%m-%d %H:%M:%S}]".format(datetime.datetime.now()))



def doRun(request, default_sleep, debug):
    print("         > Running:", request)
    time.sleep(default_sleep)
    ### Debug
    if debug == True:
        request = "echo OK"
    os.system(request)



def doFile(request, default_sleep, debug):
    print("         > File:", request)
    time.sleep(default_sleep)

    req  = request.split(" ")

    if "--create" in req:
        path  = req[ req.index("--path")  + 1].strip('\"')
        size  = req[ req.index("--size")  + 1]
        count = int(req[ req.index("--count") + 1])

        # Only specify for Windows
        if "USERPROFILE" in os.environ:
            path = path.replace("%USERPROFILE%", os.environ["USERPROFILE"])

        ### Debug
        if debug == True:
            path = "/tmp/scythe/important_files.wasted"

        # Convert size to bytes
        if size.endswith("MB"):
            size = int(size[:-2]) * 1024 * 1024

        # Creating file(s)
        for i in range(count):
            f = open(path + str(i+1), "wb")
            f.seek(size - 1)
            f.write(b"\0")
            f.close()
            # Insert a short delay between each file creation
            time.sleep(0.01)



# A standard Python XOR implementation
def doXOR(data, key): 
    return bytearray(a^b for a, b in zip(*map(bytearray, [data, key]))) 



# We'll use XOR encryption since it's simple to implement
def doCrypt(request, default_sleep, debug):
    print("         > Crypt:", request)
    time.sleep(default_sleep)

    req  = request.split(" ")

    target    = req[ req.index("--target")  + 1].strip('\"')
    password  = req[ req.index("--password")  + 1].strip('\"')

    # Only specify for Windows
    if "USERPROFILE" in os.environ:
        target = target.replace("%USERPROFILE%", os.environ["USERPROFILE"])

    if debug == True:
        target = "/tmp/scythe"

    doErase   = False
    doRecurse = False

    if "--erase" in req:
        doErase = True

    # Ignore recurse for now
    if "--recurse" in req:
        doRecurse = True

    allfiles = os.listdir(target)

    for filename in allfiles:
        outfile  = filename + ".xor"
        outfile  = os.path.join(target, outfile)
        filename = os.path.join(target, filename)

        with open(filename, mode='rb') as file:
            data = file.read()
            enc = doXOR(data, password.encode())
            out = open(outfile, 'wb+')
            out.write(enc)
            out.close()

        if doErase == True:
            os.remove(filename)



def doDownloader(request, default_sleep, debug):
    print("         > Download :", request)
    time.sleep(default_sleep)

    req  = request.split(" ")
    src  = req[ req.index("--src")  + 1].strip('\"')
    dest = req[ req.index("--dest") + 1].strip('\"')

    # Only specify for Windows
    if "USERPROFILE" in os.environ:
        dest = dest.replace("%USERPROFILE%", os.environ["USERPROFILE"])
    
    # If URL is from pastebin, make sure we pull the "raw" file
    if "pastebin.com/raw/" not in src:
        src  = src.replace("pastebin.com/","pastebin.com/raw/")

    ### Debug
    if debug == True:
        dest = "/tmp/scythe/wasted_info.txt"

    print("            Source :", src)
    print("              Dest :", dest)

    r = urllib.request.Request(src)
    rs = urllib.request.urlopen(r)
    data = rs.read()

    out = open(dest, 'wb')
    out.write(data)
    out.close()


# Not functional (yet) 
def doUploader(request, default_sleep, debug):
    print("         > Upload :", request)
    time.sleep(default_sleep)

    req   = request.split(" ")
    rpath = req[ req.index("--remotepath")  + 1].strip('\"')

    # Only specify for Windows
    if "USERPROFILE" in os.environ:
        dest = dest.replace("%USERPROFILE%", os.environ["USERPROFILE"])

    ### Debug
    if debug == True:
        dest = "/tmp/"

    print("         Upload to :", rpath)

    # Need to determine how to get the source file
    #shutil.move(source, destination)


def doController(request, default_sleep, debug):
    print("         > Controller :", request)
    time.sleep(default_sleep)

    if request == "--shutdown":
        print("\n\nController is requesting to initiate a shutdown. Proceed? [y/N] ", end="")
        theInput = input().lower()
        
        if theInput == "y":
            print("Shutting down...")
            time.sleep(default_sleep)
            os.system("shutdown /s /t 0")
        else:
            print("Skipping shutdown...")




def startEmulation(emulation_plan_url, default_sleep, test_threat, debug):
    # Keep track of supported/unsupported modules
    supported = 0
    unsupported = 0

    with urllib.request.urlopen(emulation_plan_url) as url:
        emulation_plan = json.loads(url.read().decode())
    
    # Format/output description
    desc_out = "Description : " + emulation_plan["threat"]["description"]
    desc_wrapper = textwrap.TextWrapper(width=80, initial_indent='', subsequent_indent=' ' * 14)
    desc_out = desc_wrapper.fill(text=desc_out) 

    print("Threat      :", emulation_plan["threat"]["display_name"])
    print("Platform    :", emulation_plan["threat"]["operating_system_name"].capitalize())
    print(desc_out)

    # Platform test
    # Allow to proceed for --debug and --compat modes
    if debug is False:
        if emulation_plan["threat"]["operating_system_name"] == "windows" and os.name != 'nt':
            if test_threat == False:
                print("\n[!] Error: This threat requires Windows")
                sys.exit()
            else:
                print("\n[!] Warning: This threat requires Windows")
        elif emulation_plan["threat"]["operating_system_name"] == "linux" and os.name != 'posix':
            if test_threat == False:
                print("\n[!] Error: This threat requires Linux")
                sys.exit()
            else:
                print("\n[!] Warning: This threat requires Linux")

    
    print('')
    if test_threat == False:
        print("\nReady to start? [Y/n] ", end="")
    else:
        print("\nReady to test? [Y/n] ", end="")


    # Check for Y/n
    doStart = input().lower()
    if doStart == "n":
        sys.exit()
    
    
    if test_threat == False:
        print("\nStarting emulation...")
    
    for i in emulation_plan["threat"]["script"]:
        step = emulation_plan["threat"]["script"][i]
    
        if "type" in step:
            if step["type"] == "message" or step["type"] == "delay":
    
                # Skip over 'initialization' and 'loader' steps, handle 'delay' separately
                #valid_modules = ["run","file","crypt","downloader","uploader","controller", "loader"]
                # Uploader not a valid module (yet)
                valid_modules = ["run","file","crypt","downloader","controller", "loader"]
    
                if step["type"] == "delay":
                    supported += 1
                    if test_threat == True:
                        if debug == True:
                            print("Module", step["type"], ": Supported...")
                        else:
                            print("         > Sleeping:", step["time"], "seconds...")
                            time.sleep(int(step["time"]))
                            outputTimestamp()
                elif step["module"] in valid_modules:
                    supported += 1
    
                    if test_threat == False:
                        if "rtags" in step:
                            for tag in step["rtags"]:
                                _tag = tag.split(":")
                                if(_tag[0] == "att&ck-technique"):
                                    print("\n    Emulating ATT&CK Technique : ", _tag[1], " [https://attack.mitre.org/techniques/", _tag[1] ,"]", sep = "")
                    
                    if "module" in step:
                        # Ignore 'loader'
                        if step["module"] != "loader":
                            if test_threat == True:
                                if debug == True:
                                    print("Module", step["module"], ": Supported...")
                            else:
                                if step["module"] == "run":
                                    doRun(step["request"], default_sleep, debug)
                                    outputTimestamp()
                                elif step["module"] == "file":
                                    doFile(step["request"], default_sleep, debug)
                                    outputTimestamp()
                                elif step["module"] == "crypt":
                                    doCrypt(step["request"], default_sleep, debug)
                                    outputTimestamp()
                                elif step["module"] == "downloader":
                                    doDownloader(step["request"], default_sleep, debug)
                                    outputTimestamp()
                                elif step["module"] == "uploader":
                                    doUploader(step["request"], default_sleep, debug)
                                    outputTimestamp()
                                elif step["module"] == "controller":
                                    doController(step["request"], default_sleep, debug)
                                    outputTimestamp()
    
                else:
                    unsupported += 1
                    print("[!] Warning: Module", step["module"], "is not supported...")

    if test_threat == True:
        if unsupported == 0:
            print('')
            print("Awesome! This threat appears to be fully supported!")
            print('')
        elif unsupported == 0:
            print('')
            print("This threat appears to be partially supported!")
            print('')
        else:
            print('')
            print("Bummer. This threat is not fully supported.")
            print('')


    print("Done!")




def banner():
    print('')
    print('                             `-://+sssyyyysso/:-.`                              ')
    print('                       `-/shmNmmdhhyoooooo+osyhdmNmhs+:.                        ')
    print('                   `:ohmmmhso:`                  `:/+ymMds:`                    ')
    print('                 :ymNdo/.         `.--:::::--..`       ./shmy/`                 ')
    print('              -ommmo.       ./oydNNMMMMMMMNMMMNNNmdhso/./:-.:smy/               ')
    print('            :ymd+.`     ./ymNMNmmdhhhyyhhhdmNMMMMMMMMMN+Nym   `/hdo`            ')
    print('          -ydh/`     `/shyo/-.```         ````.:+shmMMsdmNo      `+ho`          ')
    print('        `omd:        ..`                           ``::myN`        `/y+`        ')
    print('       :hm+`    `                                     :mh.           `:s-       ')
    print('      ohh. -/+shh                   //////////-       dMs              `o/      ')
    print('    `sNs`.shmddhd-                 .MMMMMMMMMMo      :MN.                /+     ')
    print('   `+h+ -sshddhhy:               ./mMMMMMMMMMMo      hMs                  -+    ')
    print('   /s: -o+yddhhs:             yhdNMMMMMMMMMMMMo     -MN.                   -+   ')
    print('  :s/ .o:-oyhhy`             `MMMMMMMMMMMMMMMMo     hMy             .yo:`   --  ')
    print(' `/y  +:+syyhy.              `MMMMMMMMMMMMMMMMo    -MM.            `ssyyyo:  :` ')
    print(' :y. :o-+-+sh:               `MMMMMMMMMMMMMMMMo    yMy             :yyys/yh`  - ')
    print(' -h  s//:-:+o                `MMMMMMMMMMMMMMMMo   .MM-              sssosyyo  + ')
    print(' +/ -+:+:-:o.                 ::::yMMMMMMMMMMMo   yMh               :sssoyyy` --')
    print(' h` :o-/-//o                      +MMMMMMMMMMMo  .MM-                syysyyy-  .')
    print(' d  +o--:/::                      +MMMMMMMMMMMo  sMh                 +oyssyy/  `')
    print('`m  +o./:++/                      +MMMMMMMMMMMo .NM-                 :oy:oyy+  `')
    print('`m  +y.:./+/                      +MMMMMMMMMMMo sMh                  +o:--sm+  .')
    print(' d` :s:/-:o+                      +MMMMMMMMMMMo`NM:                  o+:-/sm:  -')
    print(' y/ `yo:/:o/-                     +MMMMMMMMMMMooMd                  -so/+oyh`  `')
    print(' /y  ss/s:o++                     oMMMMMMMMMMMyNM:                  o+o/yoyo  ` ')
    print(' /d/ -s:o:-oo-                ```-mMMMMMMMMMMMNMm``                :s/o/oom.  . ')
    print(' -hm. +syo++s:.               ommNMMMMMMMMMMMMMMNmo               :o+/ohoy+  `` ')
    print(' `odh` syy:/oyo               sMMMMMMMMMMMMMMMMMMMy              :y/osooyo   .  ')
    print('  -ydy` +ysh/s+/              sMMMMMMMMMMMMMMMMMMMy            `/+/o+hoss`  -   ')
    print('   :oms  -sho+os              sMMMMMMMMMMMMMMMMMMMy           -s+++ysoss`  :`   ')
    print('    :ymy`  -+so+:             sMMMMMMMMMMMMMMMMMMMy         .ososs+ysh+  `-`    ')
    print('     :dNh-   `:+h+`           /yyyyyyyyyyyyyyyyyyy+       `:so+y+sysy-  .:`     ')
    print('      .ydmo`    `/y+.                                    .sysysdhhs:` `+-       ')
    print('        /hmh/`     :ss:`                                `oysymdhs/  `/o`        ')
    print('         `ommd+-     `/yy+.                         `./sddhhy+:`  -/o.          ')
    print('           `odmNs-`     `:+                   ``-:syhy+:.`     `-oy:            ')
    print('             `+dNNNs:`                     .syyyo/-`       `./yds.              ')
    print('                -ohMNNyo:`                            `.:ohNmy:`                ')
    print('                   .+yNMMMmhhso//:-..`          `-+oydNMNmy+.                   ')
    print('                       -/sdNMMMMMMMMMNmmmdddmmNNMMMMMmy+:`                      ')
    print('                            .:/osyddmNNNNNNmmdhys+:.`                           ')
    print('')
    print('                               -= PennyScythe =-')
    print('               -= Adversarial Emulation for a Penny or Less! =-')
    print('')
    print('This project is in no way associated with or endorsed by SCYTHE [scythe.io]!')




# Print basic usage
def usage():
    print('')
    print('usage: PennyScythe.py -t <threat> -r [-u <url>] [-s 5] [-c] [-d] [-h] [-l] [-r]')
    print('')


# Display verbose help
def showhelp():
    usage()
    print('Main options:')
    print('  -c, --compat            Test the specified --threat or --url for compatibility')
    print('  -d, --debug             Turn on debug options likely only useful to the author')
    print('                          of this script')
    print('  -h, --help')
    print('  -l, --list              List all available --threat modules')
    print('  -r, --run               Run the specified --threat or --url')
    print('  -s, --sleep  <seconds>  Sleep time in seconds between steps of the executed')
    print('                          --threat or --url; default is 5')
    print('  -t, --threat <threat>   Specify a threat to test --compat or --run;')
    print('                          (to view all available threat modules use --list)')
    print('  -u, --url    <url>      Supply a URL to a prepared threat plan')
    print()





def main(argv):

    # Check to see if command line args were sent
    if not argv:
        banner()
        usage()
        sys.exit()

    # Default vars
    debug               = False
    default_sleep       = 5
    threat              = ""
    run_threat          = False
    test_threat         = False
    emulation_plan_url  = ""

    # Process command line args
    try:
        opts, args = getopt.getopt(argv,"cdhlrs:t:u:",["compat","debug","help","list","run","sleep=","threat=","url="])
    except getopt.GetoptError:
        usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt in ('-h','--help'):
            banner()
            showhelp()
            sys.exit()
        elif opt in ("-d", "--debug"):
            debug = True
        elif opt in ("-l", "--list"):
            banner()
            listThreats()
            sys.exit()
        elif opt in ("-t", "--threat"):
            threat = arg
        elif opt in ("-u", "--url"):
            emulation_plan_url = arg
        elif opt in ("-s", "--sleep"):
            default_sleep = int(arg)
        elif opt in ("-r", "--run"):
            run_threat = True
        elif opt in ("-c", "--compat"):
            test_threat = True
        else:
            usage()
            sys.exit(2)


    # Set our --threat
    if threat in threats:
        if "url" in threats[threat]:
            emulation_plan_url = threats[threat]['url']


    if (run_threat == True or test_threat == True) and emulation_plan_url != "":
        try:
            banner()
            print('')
            startEmulation(emulation_plan_url, default_sleep, test_threat, debug)
        except KeyboardInterrupt:
            # Gracefully exit on ctrl-c
            print("\nBye!")
            pass
    else:
        usage()

if __name__ == "__main__":
    main(sys.argv[1:])


