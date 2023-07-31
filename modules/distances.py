import modules.ncd_preprocessing as ncdp
from pathlib import Path
import ncd2 as ncd
import csv

distance_metrics = {
    "ncd_gzip": {
        "function": "gzip_func",
    },
    "ncd_bzip2": {
        "function": "bzip2_func",
    },
    "ncd_ppmd": {
        "function": "ppmd_func",
    },
}

def distance_matrix(input_folder, output_file, method):
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    f = globals()[distance_metrics[method]["function"]]
    matrix = f(input_folder, output_file)
    return matrix

ncdp_strategies = ncdp.strategies
def bzip2_func(input_folder, output_file):
    return ncd(input_folder, output_file, "bzip2")
def  gzip_func(input_folder, output_file):
    return ncd(input_folder, output_file,  "gzip")
def  ppmd_func(input_folder, output_file):
    return ncd(input_folder, output_file,  "ppmd")
def ncd(input_folder, output_file, compressor):
    from datasource import create_factory
    from compressor import get_compressor
    from ncd2 import distance_matrix

    # TOOL IS CURRENTLY HARDCODED ###########################################
    preprocessed_folder = ncdp.preprocess_folder(input_folder, "radare-cfg", no_normalize=False)

    # PREPROCESSED FOLDER COLISION ##########################################
    factory = [create_factory(preprocessed_folder)]
    compressor = get_compressor(compressor)
    matrix = distance_matrix(factory, compressor, is_parallel=True)

    csv_reader = matrix.get_results()
    with open(output_file, "wt") as fp:
        csv_writer = csv.writer(fp)
        for pair in csv_reader:
            csv_writer.writerow([pair["x"], pair["y"], pair["ncd"]])

    return output_file