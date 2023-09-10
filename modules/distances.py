import modules.ncd_preprocessing as ncdp
from pathlib import Path
import ncd2 as ncd
import csv

distance_metrics = {
    "ncd": {
        "function": "ncd_func",
    },
}

def distance_matrix(input_folder, output_file, method, **kwargs):
    input_folder = Path(input_folder)
    output_file = Path(output_file)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    f = globals()[distance_metrics[method]["function"]]
    matrix = f(input_folder, output_file, **kwargs)
    return matrix

ncdp_strategies = ncdp.strategies
def ncd_func(input_folder, output_file, compressor, pre_processing, no_normalize, cache_path, num_threads):
    from datasource import InMemoryFactory, Filename
    from compressor import get_compressor
    import ncd2 as ncd
    output_file = f"{output_file}-{compressor}"

    preprocessed_files = ncdp.preprocess_folder(input_folder, cache_path, pre_processing, no_normalize, num_threads)
    factory = InMemoryFactory( [Filename(file) for file in preprocessed_files] )
    compressor = get_compressor(compressor)
    matrix = ncd.distance_matrix([factory], compressor, is_parallel=True)

    csv_reader = matrix.get_results()

    with open(output_file, "wt") as fp:
        csv_writer = csv.writer(fp)
        for pair in csv_reader:
            csv_writer.writerow([pair["x"], pair["y"], pair["ncd"]])

    return output_file
