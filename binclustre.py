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

parser.add_argument('--cache-path', default="caches/",
                    help='intermediary folder for cached results')
parser.add_argument('--num-threads', default=os.cpu_count(),
                    help='number of threads for parallel processes')
parser.add_argument('-d', '--distance-metric',
                    choices= d.distance_metrics.keys(), default='ncd',
                    help='distance metric for clustering')
parser.add_argument('-p', '--preprocessing',
                    choices= d.ncdp_strategies.keys(), default='radare-cfg',
                    help='NCD\'s binary pre-processing method')
parser.add_argument('--no-normalize', action='store_true',
                    help='disable adress change to sequential numbers after NCD\'s pre-processing')
parser.add_argument('-c', '--cluster',
                    choices= c.clusterers.keys(), default='damicore',
                    help='clustering method')
parser.add_argument('--cluster-number', default=None,
                    help='force cluser number, empty for auto and 0 to skip clustering')
parser.add_argument('--community-detection', default='fast',
                    choices= ["fast", "betweenness", "walktrap", "tree-modularity", "correlation-modularity", "optimal"],
                    help='community detection method for DAMICORE')
parser.add_argument('-o', '--output-path', default="results")
parser.add_argument('binary_folder',
                    help='folder containing binary files')
args = parser.parse_args()
args.num_threads = int(args.num_threads)

# Creates some necessary folders
# adds preprocessing to path for better result caching
args.cache_path = Path(args.cache_path).joinpath(args.preprocessing)
Path(args.cache_path).mkdir(parents=True, exist_ok=True)
Path(args.cache_path).joinpath("analysis/").mkdir(parents=True, exist_ok=True)
Path(args.output_path).mkdir(parents=True, exist_ok=True)
if args.preprocessing == "ghidra-pseudocode":
    Path(args.cache_path).joinpath("ghidra-project/").mkdir(parents=True, exist_ok=True)
if not args.no_normalize:
    Path(args.cache_path).joinpath("normalized/").mkdir(parents=True, exist_ok=True)
if "norm_function" not in d.ncdp_strategies[args.preprocessing].keys():
    print(f"[!] Normalization unavailable for {args.preprocessing}")
    args.no_normalize = True

# Gets distance matrix
print(f"[+] Starting distance matrix with {args.distance_metric}")
start = time()
if args.distance_metric == "ncd":
    M = d.distance_matrix(args.binary_folder,
           Path(args.cache_path).joinpath("matrix/distmat"),
           args.distance_metric, compressor="bzip2",
           cache_path=args.cache_path,
           pre_processing=args.preprocessing,
           no_normalize=args.no_normalize,
           num_threads=args.num_threads
        )
end = time()
print(f"[+] distance matrix calculated in {(end-start):.2f} s")

# Generates clustering
if not args.cluster_number or int(args.cluster_number) > 0:
    print(f"[+] Starting clustering with {args.cluster} method")
    start = time()
    if args.cluster == "damicore":
        clusters = c.cluster(M, Path(args.output_path).joinpath("clusters.txt"),
                             args.cluster, num_clusters=args.cluster_number,
                             community_detection=args.community_detection)
    end = time()
    print(f"[+] clustering finished in {(end-start):.2f} s")
else:
    print("[+] skipping clustering")
