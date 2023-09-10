# binclustre
Binclustre is a tool designed to cluster binary files, applying multiple strategies to compare its output results.
To do so, It relies on other tools to automate reverse engineering tasks and apply machine learning algorithms.

## Architecture

```
       +----------+ Distance +------------+
 Files | Distance |  Matrix  | Clustering | Clusters
------>|  Metric  |--------->|   Method   |--------->
       +----------+          +------------+
```

Binclustre's architecture divides the clustering in two steps, a pairwise distance calculation and cluster detection.
These steps are kept separate so that it's easier to integrate them into the pipeline to experiment with different methods.
The `modules/distances.py` file contains functions that creates distance matrixes and `modulres/clusters.py` contain functions for cluster detection.

## Default Folder Structure
| Path | Description |
|------|-------------|
|caches | Caches for all intermediary operations |
|results | Clustering results |
|modules | Scripts to integrate tools to the pipeline |
|datasets | Example executable binary files |

## Dependencies

The Python dependencies can be installed with the command `pip install -r requirements.txt`

After installing a tool be sure it is available in PATH, this can be made by running `export PATH=${PATH}:<path/to/binary>` for binary aplications or `export PYTHONPATH=${PYTHONPATH}:</path/to/script>` for python modules.

The available tools integrated into the clustering methods are:

- Damicore - NCD distance calculation and clustering method by simplification + community detection

        https://gitlab.com/monaco/damicore

- Radare - Creates Control-Flow Graph for binaries

        https://github.com/radareorg/radare2

- Ghidra - Creates C pseudocode for binaries by decompilation [^1]

        https://github.com/NationalSecurityAgency/ghidra

[^1]: Ghidra has to be installed at a folder called `ghidra` together with `binclustre.py`

- RetDec v4.0 - Creates C pseudocode or LLVM Intermediary Representation

        https://github.com/avast/retdec/releases/tag/v4.0

## Docker

There is a docker script that manages all dependencies automatically, it can be built with `docker build -t binclustre ./`

To run the container it's necessary to create bind mounts so it can read and write files to your filesystem, it's usage is:

```
docker run \
-v <input-folder>:/usr/src/app/input-binaries/ \
-v $PWD/results:/usr/src/app/results/ \
-v $PWD/caches:/usr/src/app/caches/ \
binclustre input-binaries/ <args>
```
