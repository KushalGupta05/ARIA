# Windows classifier

ARIA's feed consumes 15 Windows counters in a fixed order. Training and inference import the same feature list and class mapping. Class 4 represents `normal`. The feed skips that class, non-telemetry records and all-zero vectors. [Feature schema](../ML_Model/telemetry_schema.py) · [Inference code](../ML_Model/aria_classifier_feed.py)

## Reproduce the benchmark

Obtain `Train_Test_Windows_10.csv` from UNSW's TON_IoT train/test operating-system datasets. The measured file had 21,104 rows and SHA-256 `85f0827697ef5b0faf76a8b41371e95fd5e6ea3950d19ea35a9d7f35042703a8`. [UNSW TON_IoT datasets](https://research.unsw.edu.au/projects/toniot-datasets)

From the repository root, with the Python environment active, supply the path to your copy of the CSV.

```sh
python -m pip install -r ML_Model/requirements-ml.txt
python ML_Model/train_windows_model.py "path/to/Train_Test_Windows_10.csv"
```

The trainer normalizes the lab adapter name, selects the 15 counters, coerces nonnumeric or missing values to zero and encodes the eight class labels. Within each class, the first 80% of rows in file order go into training and the rest into testing. The forest uses 100 trees, balanced class weights and random seed 42. It writes the fitted model to `var/live/aria_rf_model.pkl`. [Training script](../ML_Model/train_windows_model.py)

## Results for this recipe

The run used Python 3.14, scikit-learn 1.8.0 and the versions pinned in the ML requirements. It trained on 16,881 rows and evaluated 4,223 rows. Accuracy was **0.9962** and macro F1 was **0.9864**. [Dependency versions](../ML_Model/requirements-ml.txt)

| Class | Held-out rows | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: |
| DDoS | 922 | 1.0000 | 1.0000 | 1.0000 |
| DoS | 105 | 1.0000 | 1.0000 | 1.0000 |
| Injection | 123 | 1.0000 | 1.0000 | 1.0000 |
| MITM | 3 | 1.0000 | 1.0000 | 1.0000 |
| Normal | 2,000 | 1.0000 | 1.0000 | 1.0000 |
| Password | 726 | 0.9784 | 1.0000 | 0.9891 |
| Scanning | 90 | 1.0000 | 0.8222 | 0.9024 |
| XSS | 254 | 1.0000 | 1.0000 | 1.0000 |

The split preserves file order within each class. Samples from the same capture environment can occur on both sides, and the feature list came from earlier work on this dataset. The three MITM examples make that estimate especially uncertain. Deployment evaluation would need independently labeled hosts and a check that their counter distributions resemble the training data.

## Connect an existing Wazuh lab

1. On the Windows endpoint, run `ML_Model/aria_telemetry_collector.ps1`. It records counters, process context and socket metadata as newline-delimited JSON under `C:\wazuh_telemetry\aria_metrics.json`.
2. Configure the Wazuh agent to collect that file with the `json` log format. The manager must write JSON archives that include the forwarded records. [Wazuh log collection](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/monitoring-log-files.html)
3. Run `python ML_Model/aria_classifier_feed.py` on the machine with access to the manager's Docker container. Set `ARIA_WAZUH_CONTAINER` if its name differs from `single-node-wazuh.manager-1`. The feed tails new records in `/var/ossec/logs/archives/archives.json`.
4. Start the retrieval worker in another terminal, then run `python ML_Model/frontend_api.py` to serve live cases on loopback. Build the console first using the project quickstart. [Investigation worker](../ML_Model/RAG_Pipeline/README.md)

The collector records endpoint details. The demo uses synthetic records in a separate database. To change the live state directory, set `ARIA_STATE_DIR` consistently for the trainer, classifier, worker and API.
