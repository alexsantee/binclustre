import os, sys
import csv
from pathlib import Path

clusterers = {
    "damicore": {
        "function": "damicore_func",
    },
}

"""
Does clustering using a given clusterer
inpath is the location with static analysis files
outpath is the clustering result destination
"""
def cluster(distance_matrix, output_file, method, num_clusters=None):
    f = globals()[clusterers[method]["function"]]
    clusters = f(distance_matrix, output_file, num_clusters)
    return clusters

def damicore_func(distance_matrix, output_file, num_clusters=None, community_detection_name="fast",
                  is_normalize_matrix=True,is_normalize_weights=True):
    import clustering as c
    import tree_simplification as nj
    from tree import to_graph, newick_format
    import ncd2 as ncd
    from _utils import normalize_list

    # Read matrix from file
    with open(distance_matrix, "rt") as csv_file:
        csv_reader = csv.DictReader(csv_file, fieldnames=["x","y","ncd"])
        results = list(csv_reader)
    if not is_normalize_matrix:
        m, (ids,_) = ncd.to_matrix(results)
    else:
        ds = normalize_list(list(float(result['ncd']) for result in results))
        normalized_results = [ncd.NcdResult(result, ncd=dist) for result, dist in zip(results, ds)]
        m, (ids,_) = ncd.to_matrix(normalized_results)

    # Simplifying step
    sys.stderr.write('Simplifying graph...\n')
    tree = nj.neighbor_joining(m, ids)
    g = to_graph(tree)

    # Remove non-positive lengths and change them to an epsilon
    for e in g.es:
        if e["length"] <= 0:
            sys.stderr.write(f"Non positive length {e['length']} set to epsilon!\n")
            e["length"] = 1e-12

    # Saves tree intermediate result
    output_folder = Path(output_file).parent
    tree_filename = Path("tree.newick")
    with open(output_folder.joinpath(tree_filename), 'wt') as f:
        f.write(newick_format(tree))

    # Community detection
    sys.stderr.write('Clustering elements...\n')
    membership, _, _ = c.tree_clustering(g, ids,
        is_normalize_weights=is_normalize_weights,
        num_clusters=num_clusters,
        community_detection_name=community_detection_name)

    # Saves clustering results
    with open(output_file, "wt") as fp:
        for k,v in membership.items():
            fp.write(f"{k},{v}\n")

    return output_file
