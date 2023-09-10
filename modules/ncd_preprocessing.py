import os
import shutil
import subprocess
import re
from time import time
from multiprocessing import Pool
from pathlib import Path

strategies = {
    "angr-cfg": {
        "function": "angr_func",
        "norm_function": "angr_norm",
    },
    "radare-cfg": {
        "function": "radare_func",
        "norm_function": "radare_norm",
    },
    "ghidra-pseudocode": {
        "function": "ghidra_func",
        "norm_function": "ghidra_norm",
    },
    "retdec-llvmir": {
        "function": "retdec_llvm_func",
    },
    "retdec-pseudocode": {
        "function": "retdec_pseudocode_func",
    },
    "strings": {
        "function": "strings_func",
    },
    "raw-binary": {
        "function" : "raw_func",
    },
}

"""
Does static analysis with static_tool
binary is the binary name
inpath is the binary location
outpath is the analysis result destination
"""
def analyse(tool, inpath, outpath):
    f = globals()[strategies[tool]["function"]]
    f(inpath,outpath)

"""
Does an adress normalization to the static_tool output
binary is the binary name
inpath is the binary location
outpath is the analysis result destination
"""
def normalize(tool,inpath,outpath):
    f = globals()[strategies[tool]["norm_function"]]
    f(inpath,outpath)

"""
Executes preprocessing for a file
tool is the application that executes the preprocessing
inputbinary is the binary name
binary_folder is the folder containing the binary
analysis is the preprocessing result destination
no_normalize indicates if the normalization step should be skipped
"""
def preprocess_file(tool, inpath, outpath, no_normalize=False):
    print(f"[+] Analysing {inpath.name}")
    analysis_outpath = outpath.joinpath("analysis/").joinpath(inpath.name)
    if os.path.isfile(analysis_outpath):
        print(f"[+] Using cached version at {analysis_outpath}")
    else:
        start = time()
        analyse(tool, inpath, analysis_outpath)
        end = time()
        print(f"[+] {inpath.name} analysed in {(end-start):.2f} s")


    if not no_normalize:
        print(f"[+] Normalizing {inpath.name}")
        normalize_outpath = outpath.joinpath("normalized/").joinpath(inpath.name)
        if os.path.isfile(normalize_outpath):
            print(f"[+] Using cached version at {normalize_outpath}")
        else:
            start = time()
            normalize(tool, analysis_outpath, normalize_outpath)
            end = time()
            print(f"[+] {inpath.name} normalized in {(end-start):.2f} s")

def preprocess_folder(input_folder, output_folder, tool, no_normalize=False, num_threads=os.cpu_count()):
    binaries = os.listdir(input_folder)
    binaries.sort()
    outpath = Path(output_folder)
    TASKS = [
        (tool, input_folder.joinpath(binary), outpath, no_normalize)
        for binary in binaries
    ]
    print(f"[+] Starting pre-processing with {tool} method")
    with Pool(num_threads) as p:
        p.starmap(preprocess_file, TASKS)

    # return list of pre_processed files
    outfiles = []
    if no_normalize:
        for binary in binaries:
            outfiles.append( str(outpath.joinpath("analysis/").joinpath(binary)) )
    else:
        for binary in binaries:
            outfiles.append( str(outpath.joinpath("normalized/").joinpath(binary)) )
    return outfiles

# Static Analysis functions:
def angr_func(inpath,outpath):
    import angrutils as au
    import modules.angr_module as angr_m
    import logging

    logging.getLogger('pyvex.lifting.libvex').setLevel('ERROR')
    logging.getLogger('cle.backends.externs').setLevel('ERROR')
    logging.getLogger('cle.loader').setLevel('ERROR')

    p = au.angr.Project(inpath, auto_load_libs=False)
    cfg = p.analyses.CFGFast(normalize=True)
    angr_m.generate_cg(cfg, inpath.name, outpath.parent)

def radare_func(inpath,outpath):
    p = subprocess.run(["r2", "-A", "-q", "-c", "agCj", inpath], capture_output=True)
    with open(outpath, "wb") as fp:
        fp.write(p.stdout)
    for line in p.stderr.decode().split("\n"):
        print(f"{inpath.name}: {line}")
    if p.returncode != 0:
        print(f"[!] radare returned {p.returncode} for {inpath.name}")

def ghidra_func(inpath,outpath):
    proj_path = outpath.parents[1].joinpath("ghidra-project/")
    p = subprocess.run(["ghidra/support/analyzeHeadless",
                        proj_path, inpath.name,
                        "-import", inpath,
                        "-scriptPath", "./modules/",
                        "-postScript", "./modules/ghidra_decompiler.py",
                        outpath],
                        stderr=subprocess.PIPE,
                        stdout=subprocess.DEVNULL,
                        timeout=None)
    for line in p.stderr.decode().split("\n"):
        print(f"{inpath.name}: {line}")
    if p.returncode != 0:
        print(f"[!] ghidra returned {p.returncode} for {inpath.name}")
    shutil.rmtree(proj_path.joinpath(f"{inpath.name}.rep"))
    os.remove(proj_path.joinpath(f"{inpath.name}.gpr"))

def retdec_llvm_func(inpath,outpath):
    p = subprocess.run(["retdec-decompiler.py", "--keep-unreachable-funcs", "--stop-after", "bin2llvmir",
                        "-o", outpath, inpath],
                       stderr=subprocess.PIPE, stdout=subprocess.DEVNULL)
    for line in p.stderr.decode().split("\n"):
        print(f"{inpath.name}: {line}")
    if p.returncode != 0:
        print(f"[!] RetDec returned {p.returncode} for {inpath.name}")
    """
    # The --Os optimization should give better results, but crashes in some cases
    p = subprocess.run(["opt", f"{outpath}/results/{binary}.bc", #"--Os",
                       "-o", f"{outpath}/results/{binary}.bc"],
                       stderr=subprocess.PIPE, stdout=subprocess.DEVNULL)
    for line in p.stderr.decode().split("\n"):
        print(f"{binary}: {line}")
    if p.returncode != 0:
        print(f"[!] opt returned {p.returncode} for {binary}")
    """
    # Removes extra files
    filelist = os.listdir(outpath.parent)
    for file in filelist:
        extension = file.split(".")[-1]
        fullpath = outpath.parent.joinpath(file)
        if extension in {"bc", "dsm", "json"}:
            os.remove(fullpath)
        elif extension == "ll":
            os.rename(fullpath, str(fullpath)[:-3])

def retdec_pseudocode_func(inpath,outpath):
    p = subprocess.run(["retdec-decompiler.py", "--keep-unreachable-funcs", inpath,
                        "-o", outpath],
                       stderr=subprocess.PIPE, stdout=subprocess.DEVNULL)
    for line in p.stderr.decode().split("\n"):
        print(f"{inpath.name}: {line}")
    if p.returncode != 0:
        print(f"[!] retdec returned {p.returncode} for {inpath.name}")
    # Removes extra files
    filelist = os.listdir(outpath.parent)
    for file in filelist:
        extension = file.split(".")[-1]
        fullpath = outpath.parent.joinpath(file)
        if extension in {"bc", "dsm", "json", "ll"}:
            os.remove(fullpath)
        elif extension == "c":
            os.rename(fullpath, str(fullpath)[:-2])

def strings_func(inpath,outpath):
    p = subprocess.run(["strings", inpath], capture_output=True)
    with open(outpath, "wb") as fp:
        fp.write(p.stdout)
    for line in p.stderr.decode().split("\n"):
        print(f"{inpath.name}: {line}")
    if p.returncode != 0:
        print(f"[!] strings returned {p.returncode} for {inpath.name}")

def raw_func(inpath,outpath):
    subprocess.run(["cp", inpath, outpath],
                   capture_output=subprocess.DEVNULL)

# Normalization functions:
def angr_norm(inpath, outpath):
    with open(inpath, "r") as callgraphfile:
        #print(f"[+] Analysing callgraph: {inpath}/results/{infile}")

        callgraph = callgraphfile.read()

        alladdressesindex = 0
        alladdressesmatches = {}
        alladdressesreplaces = {}
        hexaddresses = re.findall("0x[0-9a-f]+\\)", callgraph)
        subaddresses = re.findall("sub_[0-9a-f]+\\(", callgraph)

        for addr in hexaddresses:
            addr = addr[:-1]
            tmpaddr = addr[2:]
            tmpaddr = tmpaddr.lstrip("0")

            if tmpaddr not in alladdressesmatches:
                alladdressesindex += 1
                alladdressesmatches[tmpaddr] = alladdressesindex
                alladdressesreplaces[addr] = alladdressesindex
            elif addr not in alladdressesreplaces:
                alladdressesreplaces[addr] = alladdressesmatches[tmpaddr]

        for addr in subaddresses:
            addr = addr[:-1]
            tmpaddr = addr[4:]
            tmpaddr = tmpaddr.lstrip("0")

            if tmpaddr not in alladdressesmatches:
                alladdressesindex += 1
                alladdressesmatches[tmpaddr] = alladdressesindex
                alladdressesreplaces[addr] = alladdressesindex
            elif addr not in alladdressesreplaces:
                alladdressesreplaces[addr] = alladdressesmatches[tmpaddr]

        print(f"[+] Found addresses to replace: {len(alladdressesreplaces)}")
        pointeraddressindex = 0

        for addr in alladdressesreplaces:

            indexstr = str(hex(alladdressesreplaces[addr]))[2:].rjust(8, "0")
            normalized = f"0x{indexstr}"

            callgraph = callgraph.replace(addr, normalized)
            pointeraddressindex += 1

        with open(outpath, "w") as pseudocodenormalizedfile:
            #print(f"[+] Writting normalized callgraph: {inpath}/normalized/{infile}")
            pseudocodenormalizedfile.write(callgraph)

def radare_norm(inpath, outpath):
    with open(inpath, "r") as callgraphfile:
        callgraph = callgraphfile.read()

        alladdressesindex = 0
        alladdressesmatches = {}
        alladdressesreplaces = {}
        hexaddresses = re.findall("0x[0-9a-f]{8,}", callgraph)
        unkaddresses = re.findall("unk.0x[0-9a-f]+[\\/\"]", callgraph)
        fcnaddresses = re.findall("fcn.[0-9a-f]+[\\/\"]", callgraph)

        for addr in hexaddresses:
            tmpaddr = addr[2:]
            tmpaddr = tmpaddr.lstrip("0")

            if tmpaddr not in alladdressesmatches:
                alladdressesindex += 1
                alladdressesmatches[tmpaddr] = alladdressesindex
                alladdressesreplaces[addr] = alladdressesindex
            elif addr not in alladdressesreplaces:
                alladdressesreplaces[addr] = alladdressesmatches[tmpaddr]

        for addr in unkaddresses:
            addr = addr[:-1]
            tmpaddr = addr[6:]
            tmpaddr = tmpaddr.lstrip("0")

            if tmpaddr not in alladdressesmatches:
                alladdressesindex += 1
                alladdressesmatches[tmpaddr] = alladdressesindex
                alladdressesreplaces[addr] = alladdressesindex
            elif addr not in alladdressesreplaces:
                alladdressesreplaces[addr] = alladdressesmatches[tmpaddr]

        for addr in fcnaddresses:
            addr = addr[:-1]
            tmpaddr = addr[6:]
            tmpaddr = tmpaddr.lstrip("0")

            if tmpaddr not in alladdressesmatches:
                alladdressesindex += 1
                alladdressesmatches[tmpaddr] = alladdressesindex
                alladdressesreplaces[addr] = alladdressesindex
            elif addr not in alladdressesreplaces:
                alladdressesreplaces[addr] = alladdressesmatches[tmpaddr]

        print(f"[+] Found addresses to replace: {len(alladdressesreplaces)}")
        pointeraddressindex = 0

        for addr in alladdressesreplaces:

            indexstr = str(hex(alladdressesreplaces[addr]))[2:].rjust(8, "0")
            normalized = f"0x{indexstr}"

            callgraph = callgraph.replace(addr, normalized)
            pointeraddressindex += 1

        with open(outpath, "w") as pseudocodenormalizedfile:
            #print(f"[+] Writting normalized callgraph: {inpath}/normalized/{infile}")
            pseudocodenormalizedfile.write(callgraph)

def ghidra_norm(inpath, outpath):
    normalize_string_pointers = True
    with open(inpath, "r") as pseudocodefile:
       #print(f"[+] Analysing pseudocode: {inpath}/results/{infile}")

       pseudocode = pseudocodefile.read()

       # fix main function
       mainaddr = re.search("_uClibc_main\\((FUN_[0-9a-f]{8,})", pseudocode)
       if mainaddr is not None:
           mainaddr = mainaddr.group(1)
           pseudocode = pseudocode.replace(mainaddr, "main")

       # search and replace pointers
       pointeraddresses = []
       addresses = re.findall("PTR_[A-Z]{3}_[0-9a-f]{8,}", pseudocode)

       for addr in addresses:
           if addr.startswith("PTR"):
               if addr not in pointeraddresses:
                   pointeraddresses.append(addr)

       print(f"[+] Found addresses: {len(addresses)}")
       print(f"[+] Found pointer addresses: {len(pointeraddresses)}")
       pointeraddressindex = 0
       for addr in pointeraddresses:
           indexstr = str(hex(pointeraddressindex))[2:].rjust(8, "0")
           normalized = f"PTR_{indexstr}"

           pseudocode = pseudocode.replace(addr, normalized)
           pointeraddressindex += 1


       # search and replace data, functions and labels
       dataaddresses = []
       functionaddresses = []
       labeladdresses = []
       addresses = re.findall("[A-Z]{3}_[0-9a-f]{8,}", pseudocode)

       for addr in addresses:
           if addr.startswith("DAT"):
               if addr not in dataaddresses:
                   dataaddresses.append(addr)

           elif addr.startswith("FUN"):
               if addr not in functionaddresses:
                   functionaddresses.append(addr)

           elif addr.startswith("LAB"):
               if addr not in labeladdresses:
                   labeladdresses.append(addr)

       print(f"[+] Found addresses: {len(addresses)}")
       print(f"[+] Found data addresses: {len(dataaddresses)}")
       print(f"[+] Found function addresses: {len(functionaddresses)}")
       print(f"[+] Found label addresses: {len(labeladdresses)}")

       dataaddressindex = 0
       functionaddressindex = 0
       labeladdressindex = 0

       for addr in dataaddresses:
           indexstr = str(hex(dataaddressindex))[2:].rjust(8, "0")
           normalized = f"DAT_{indexstr}"

           pseudocode = pseudocode.replace(addr, normalized)
           dataaddressindex += 1

       for addr in functionaddresses:
           indexstr = str(hex(functionaddressindex))[2:].rjust(8, "0")
           normalized = f"FUN_{indexstr}"

           pseudocode = pseudocode.replace(addr, normalized)
           functionaddressindex += 1

       for addr in labeladdresses:
           indexstr = str(hex(labeladdressindex))[2:].rjust(8, "0")
           normalized = f"LAB_{indexstr}"

           pseudocode = pseudocode.replace(addr, normalized)
           labeladdressindex += 1

       # search and replace string pointers
       if normalize_string_pointers:
           string_pointers = re.findall("PTR_s_[a-zA-z0-9_]+", pseudocode)

           print(f"[+] Found string pointers: {len(string_pointers)}")

           for string_pointer in string_pointers:
               normalized_string = string_pointer.replace("PTR_s_", "")
               normalized_string = normalized_string[:normalized_string.rfind("_")]
               normalized_string = f"\"{normalized_string}\""
               normalized_string = normalized_string.replace("_", " ")

               pseudocode = pseudocode.replace(string_pointer, normalized_string)

       # write normalized pseudocode to output file
       with open(outpath, "w") as pseudocodenormalizedfile:
           #print(f"[+] Writting normalized pseudocode: {inpath}/normalized/{infile}")
           pseudocodenormalizedfile.write(pseudocode)
