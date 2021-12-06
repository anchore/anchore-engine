import typing

from anchore_engine.analyzers.syft.handlers import (
    modules_by_artifact_type,
    modules_by_engine_type,
)
from anchore_engine.clients.syft_wrapper import run_syft

from .adapters import FilteringEngineAdapter


def catalog_image(
    tmp_dir: str, image_oci_dir: str, package_filtering_enabled=True
) -> typing.Tuple[dict, dict]:
    """
    Catalog the given image with syft, keeping only select artifacts in the returned results

    :param tmp_dir: path to directory where the image data resides
    :param image_oci_dir: path to the directory for temp file construction
    :return: tuple of engine formatted result and raw syft output to allow it to be used downstream if needed
    """
    syft_analysis = run_syft(tmp_dir_path=tmp_dir, oci_image_dir_path=image_oci_dir)
    output_adapter = FilteringEngineAdapter(syft_analysis, package_filtering_enabled)
    converted_output = output_adapter.convert()
    return converted_output, syft_analysis
