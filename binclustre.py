#!/bin/env python3

import argparse
import os
from time import time
from pathlib import Path
import shutil
from modules import distances as d
from modules import clusters  as c

parser = argparse.ArgumentParser(
    prog = 'Binclustre',
    description = 'Creates clusters to determine similarity from binaries')

parser.add_argument('--analysis-path', default="outputs/",
                    help='intermediary folder for cached results')
parser.add_argument('--num-threads', default=os.cpu_count(),
                    help='number of threads for parallel processes')
parser.add_argument('-d', '--distance-metric',
                    choices= d.distance_metrics.keys(), default='ncd_bzip2',
                    help='distance metric for clustering')
parser.add_argument('-p', '--preprocessing',
                    choices= d.ncdp_strategies.keys(), default='radare-cfg',
                    help='NCD\'s binary pre-processing method')
parser.add_argument('--no-normalize', action='store_true',
                    help='disable adress change to sequential numbers after NCD\'s pre-processing')
parser.add_argument('-c', '--cluster',
                    choices= c.clusterers.keys(), default='damicore',
                    help='clustering method')
parser.add_argument('-o', '--output-path', default="results")
parser.add_argument('binary_folder',
                    help='folder containing binary files')
args = parser.parse_args()

# Creates some necessary folders (shall this become a setup function?)
# adds analysis name to path for better result caching
args.analysis_path += f"{args.preprocessing}/"
Path(args.analysis_path).mkdir(parents=True, exist_ok=True)
Path(f"{args.analysis_path}/results").mkdir(parents=True, exist_ok=True)
Path(f"{args.output_path}").mkdir(parents=True, exist_ok=True)
if args.preprocessing == "ghidra-pseudocode":
    Path(f"{args.analysis_path}/ghidra-project").mkdir(parents=True, exist_ok=True)
if not args.no_normalize:
    Path(f"{args.analysis_path}/normalized").mkdir(parents=True, exist_ok=True)
if "norm_function" not in d.ncdp_strategies[args.preprocessing].keys():
    print(f"[!] Normalization unavailable for {args.preprocessing}")
    args.no_normalize = True

# Gets distance matrix
M = d.distance_matrix(args.binary_folder, f"{args.analysis_path}/matrix/distmat.csv", args.distance_metric)

# Generates clustering
print(f"[+] Starting clustering with {args.cluster} method")
start = time()
clusters = c.cluster(M, f"{args.output_path}/clusters.txt", "damicore")
end = time()
print(f"[+] clustering finished in {(end-start):.2f} s")