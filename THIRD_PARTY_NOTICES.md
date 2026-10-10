# Third-Party Data Notices

## CICIDS2017-derived ready-to-run benchmark subset

Mabeli Sentinel includes a small verified subset of records derived from the public `transformer112/cicids2017-ids-dataset` repository so the detection pipeline remains functional when the machine has no network access.

- Upstream dataset: CICIDS2017-derived public sample
- Repository: https://huggingface.co/datasets/transformer112/cicids2017-ids-dataset
- Repository license as published on the dataset page: MIT
- Original research dataset: Canadian Institute for Cybersecurity / University of New Brunswick CICIDS2017
- Included file: `ml-service/data/benchmark/cicids2017_verified_preview.csv`
- Purpose: application bootstrap and end-to-end benchmark validation

The bundled subset is intentionally labelled in model metadata as `verified-preview-fallback`. It is not represented as the full official CICIDS2017 dataset and should not be used to claim final research performance. The application supports full official-dataset retraining for the project's final evaluation.
