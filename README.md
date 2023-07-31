# binclustre
Binclustre is a tool designed to cluster binary files, applying multiple strategies to compare its output results.
To do so, It relies on other tools to automate reverse engineering tasks and apply machine learning algorithms.

## Dependencies
- Damicore - Clustering and classification tool

        https://gitlab.com/monaco/damicore

- Ghidra - Reverse Engineering tool

        https://github.com/NationalSecurityAgency/ghidra

## Folder Structure
| Path | Description |
|------|-------------|
|auxiliares | Scripts used to assist with Reverse Engineering tasks |
|datasets | Data used to label the clustering output |
|input-binaries | Binary files that will be used for RE tasks and Clustering |
|notebooks | Jupyter notebooks used for prototyping this tool |
|outputs | Outputs from RE tasks |
|results | Clustering results |