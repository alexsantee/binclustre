import os
import shutil
import subprocess
import re
from time import time
from multiprocessing import Pool

strategies = {
    "angr-cfg": {
        "function": "angr_func",
        "norm_function": "angr_norm",
        "suffix": ".cg"
    },
    "radare-cfg": {
        "function": "radare_func",
        "norm_function": "radare_norm",
        "suffix": ".json"
    },
    "ghidra-pseudocode": {
        "function": "ghidra_func",
        "norm_function": "ghidra_norm",
        "suffix": ".c"
    },
    "retdec-llvmir": {
        "function": "retdec_llvm_func",
        "suffix": ".bc"
    },
    "retdec-pseudocode": {
        "function": "retdec_pseudocode_func",
        "suffix": ".c"
    },
    "strings": {
        "function": "strings_func",
        "suffix": ".txt"
    },
    "raw-binary": {
        "function" : "raw_func",
        "suffix": ".elf"
    },
}

"""
Does static analysis with static_tool
binary is the binary name
inpath is the binary location
outpath is the analysis result destination
"""
def analyse(static_tool, binary, inpath, outpath):
    f = globals()[strategies[static_tool]["function"]]
    f(binary, inpath, outpath)

"""
Does an adress normalization to the static_tool output
binary is the binary name
inpath is the binary location
outpath is the analysis result destination
"""
def normalize(tool, binary, inpath):
    suffix = strategies[tool]["suffix"]
    f = globals()[strategies[tool]["norm_function"]]
    f(f"{binary}{suffix}", inpath)

"""
Executes preprocessing for a file
tool is the application that executes the preprocessing
inputbinary is the binary name
binary_folder is the folder containing the binary
analysis is the preprocessing result destination
no_normalize indicates if the normalization step should be skipped
"""
def preprocess_file(tool, inputbinary, binary_folder, analysis_path, no_normalize=False):
    suffix = strategies[tool]["suffix"]

    print(f"[+] Analysing {inputbinary}")
    if os.path.isfile(f"{analysis_path}results/{inputbinary}{suffix}"):
        print(f"[+] Using cached version at {analysis_path}results/{inputbinary}{suffix}")
    else:
        start = time()
        analyse(tool, inputbinary, binary_folder, analysis_path)
        end = time()
        print(f"[+] {inputbinary} analysed in {(end-start):.2f} s")


    if not no_normalize:
        print(f"[+] Normalizing {inputbinary}")
        if os.path.isfile(f"{analysis_path}normalized/{inputbinary}{suffix}"):
            print(f"[+] Using cached version at {analysis_path}normalized/{inputbinary}{suffix}")
        else:
            start = time()
            normalize(tool, inputbinary, analysis_path)
            end = time()
            print(f"[+] {inputbinary} normalized in {(end-start):.2f} s")

def preprocess_folder(input_folder, tool, no_normalize=False):
    inputbinaries = os.listdir(input_folder)
    inputbinaries.sort()
    # CACHE PATH CURRENTLY HARDCODED ###########################################
    output_folder = "outputs/"
    TASKS = [
        (tool, inputbinary, input_folder, f"{output_folder}/{tool}/", no_normalize)
        for inputbinary in inputbinaries
    ]
    # NUMBER OF THREADS HARDCODED ##############################################
    print(f"[+] Starting pre-processing with {tool} method")
    with Pool(1+0*os.cpu_count()) as p:
        p.starmap(preprocess_file, TASKS)
    if no_normalize:
        return f"{output_folder}/{tool}/results/"
    return f"{output_folder}/{tool}/normalized/"

# Static Analysis functions:
def angr_func(binary, inpath, outpath):
    import angrutils as au
    import modules.angr_module as angr_m
    import logging

    logging.getLogger('pyvex.lifting.libvex').setLevel('ERROR')
    logging.getLogger('cle.backends.externs').setLevel('ERROR')
    logging.getLogger('cle.loader').setLevel('ERROR')

    p = au.angr.Project(f"{inpath}/{binary}", auto_load_libs=False)
    cfg = p.analyses.CFGFast(normalize=True)
    angr_m.generate_cg(cfg, binary, f"{outpath}/results/")

def radare_func(binary, inpath, outpath):
    p = subprocess.run(["r2", "-A", "-q", "-c", "agCj", f"{inpath}/{binary}"], capture_output=True)
    print(f"{outpath}/results/{binary}.json")
    with open(f"{outpath}/results/{binary}.json", "wb") as fp:
        fp.write(p.stdout)
    for line in p.stderr.decode().split("\n"):
        print(f"{binary}: {line}")
    if p.returncode != 0:
        print(f"[!] radare returned {p.returncode} for {binary}")

def ghidra_func(binary, inpath, outpath):
    p = subprocess.run(["ghidra/support/analyzeHeadless", f"{outpath}/ghidra-project",
                    f"{binary}", "-import", f"{inpath}/{binary}", "-scriptPath",
                    "./auxiliaries/ghidra/scripts/", "-postScript",
                    "./auxiliaries/ghidra/scripts/decompiler.py", f"{outpath}/results/{binary}.c"],
                    stderr=subprocess.PIPE, stdout=subprocess.DEVNULL, timeout=None)
    for line in p.stderr.decode().split("\n"):
        print(f"{binary}: {line}")
    if p.returncode != 0:
        print(f"[!] ghidra returned {p.returncode} for {binary}")
    shutil.rmtree(f"{outpath}/ghidra-project/{binary}.rep")
    os.remove(f"{outpath}/ghidra-project/{binary}.gpr")

def retdec_llvm_func(binary, inpath, outpath):
    p = subprocess.run(["retdec-decompiler.py", "--keep-unreachable-funcs", "--stop-after", "bin2llvmir",
                        "-o", f"{outpath}/results/{binary}.bc", f"{inpath}/{binary}"],
                       stderr=subprocess.PIPE, stdout=subprocess.DEVNULL)
    for line in p.stderr.decode().split("\n"):
        print(f"{binary}: {line}")
    if p.returncode != 0:
        print(f"[!] RetDec returned {p.returncode} for {binary}")
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
    subprocess.run(["rm", f"{outpath}/results/{binary}.config.json", f"{outpath}/results/{binary}.ll", f"{outpath}/results/{binary}.dsm"], capture_output=subprocess.DEVNULL)

def retdec_pseudocode_func(binary, inpath, outpath):
    p = subprocess.run(["retdec-decompiler.py", "--keep-unreachable-funcs", f"{inpath}/{binary}",
                        "-o", f"{outpath}/results/{binary}.c"],
                       stderr=subprocess.PIPE, stdout=subprocess.DEVNULL)
    for line in p.stderr.decode().split("\n"):
        print(f"{binary}: {line}")
    if p.returncode != 0:
        print(f"[!] retdec returned {p.returncode} for {binary}")
    # Removes extra files
    subprocess.run(["rm", f"{outpath}/results/{binary}.config.json", f"{outpath}/results/{binary}.ll", f"{outpath}/results/{binary}.bc", f"{outpath}/results/{binary}.dsm"], capture_output=subprocess.DEVNULL)

def strings_func(binary, inpath, outpath):
    p = subprocess.run(["strings", f"{inpath}/{binary}"], capture_output=True)
    with open(f"{outpath}/results/{binary}.txt", "wb") as fp:
        fp.write(p.stdout)
    for line in p.stderr.decode().split("\n"):
        print(f"{binary}: {line}")
    if p.returncode != 0:
        print(f"[!] strings returned {p.returncode} for {binary}")

def raw_func(binary, inpath, outpath):
    subprocess.run(["cp", f"{inpath}/{binary}", f"{outpath}/results/{binary}.elf"],
                   capture_output=subprocess.DEVNULL)

# Normalization functions:
def angr_norm(infile, inpath):
    with open(f"{inpath}/results/{infile}", "r") as callgraphfile:
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

        with open(f"{inpath}/normalized/{infile}", "w") as pseudocodenormalizedfile:
            #print(f"[+] Writting normalized callgraph: {inpath}/normalized/{infile}.cg")
            pseudocodenormalizedfile.write(callgraph)

def radare_norm(infile, inpath):
    with open(f"{inpath}/results/{infile}", "r") as callgraphfile:
        #print(f"[+] Analysing callgraph: {inpath}/results/{infile}")

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

        with open(f"{inpath}/normalized/{infile}", "w") as pseudocodenormalizedfile:
            #print(f"[+] Writting normalized callgraph: {inpath}/normalized/{infile}")
            pseudocodenormalizedfile.write(callgraph)

def ghidra_norm(infile, inpath):
    normalize_string_pointers = True
    with open(f"{inpath}/results/{infile}", "r") as pseudocodefile:
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
       with open(f"{inpath}/normalized/{infile}", "w") as pseudocodenormalizedfile:
           #print(f"[+] Writting normalized pseudocode: {inpath}/normalized/{infile}")
           pseudocodenormalizedfile.write(pseudocode)
