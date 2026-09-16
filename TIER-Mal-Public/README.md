# TIER-Mal-Public

Mã nguồn huấn luyện/tấn công RL trên PE cùng detector custom và các detector
đánh giá độc lập. Repository này chỉ chứa mã, cấu hình và hai wheel cần cho
STOKE; dataset, mẫu PE, checkpoint và model đã huấn luyện không được phát hành.

## Cấu trúc

```text
proposed/                       RL package, action và môi trường Gym
detectors/custom_rl/xgboost/    Detector HTTP dùng cho target=custom
detectors/evaluation/           Sorel, DeepMal, CNN và EMBER2024 độc lập
scripts/                        Cài môi trường và entrypoint chạy
configs/requirements.txt        Dependency đã pin của RL (Python 3.7.17)
runtime/                        Dữ liệu, IPC/share, log lúc chạy (không commit)
```

## Yêu cầu hệ thống

Mỗi nhóm có virtual environment riêng để tránh xung đột TensorFlow/Torch.
Các script chỉ cài package, **không tải dataset hay model**.

| Thành phần | Python | Lệnh dựng môi trường |
| --- | --- | --- |
| RL core | 3.7.17 | `PYTHON_BIN=python3.7 bash scripts/setup_rl_env.sh` |
| STOKE + funcval cục bộ | >=3.9 | `PYTHON_BIN=python3.9 bash scripts/setup_stoke_env.sh` |
| Custom detector | 3.10–3.11 | `PYTHON_BIN=python3.10 bash scripts/setup_detector_env.sh custom-xgboost` |
| Sorel | 3.9 | `PYTHON_BIN=python3.9 bash scripts/setup_detector_env.sh sorel` |
| DeepMal | 3.9 | `PYTHON_BIN=python3.9 bash scripts/setup_detector_env.sh deepmal` |
| CNN | 3.7 | `PYTHON_BIN=python3.7 bash scripts/setup_detector_env.sh cnn` |
| EMBER2024 | >=3.10 | `PYTHON_BIN=python3.10 bash scripts/setup_detector_env.sh ember` |

`git` cần có khi cài Sorel vì dependency `ember` được lấy từ Git. Cài Python
qua package manager/pyenv là việc của máy chủ; các script không tự build Python,
không ghi vào `$HOME` và không tải artifact ngoài repo.

### Nguồn hướng dẫn môi trường gốc

Các lệnh `scripts/setup_*_env.sh` bên trên là bản chuẩn hóa cho repo public.
Bảng dưới ghi lại hướng dẫn cài môi trường gốc hoặc file dependency gốc đã được
dùng để tạo các script này.

| Thành phần | Nguồn gốc | Hướng dẫn/env gốc | Lệnh chuẩn hóa trong repo này |
| --- | --- | --- | --- |
| EMBER2024 | `https://github.com/futurecomputing4ai/EMBER2024` | README gốc: `git clone https://github.com/FutureComputing4AI/EMBER2024.git`, `cd EMBER2024/`, `pip install .`; `pyproject.toml` yêu cầu Python `>=3.10` | `PYTHON_BIN=python3.10 bash scripts/setup_detector_env.sh ember` |
| DeepMal | `https://github.com/jaketae/deep-malware-detection` | README gốc: `python -m venv venv`, `source venv/bin/activate`, `pip install -U pip wheel`, `pip install -r requirements.txt` | `PYTHON_BIN=python3.9 bash scripts/setup_detector_env.sh deepmal` |
| CNN | `https://github.com/cridin1/malware-classification-CNN` | README gốc mô tả dataset/model, không có lệnh venv đầy đủ; repo public dùng `detectors/evaluation/malware-classification-CNN/requirements.txt` để pin TensorFlow/Keras runtime | `PYTHON_BIN=python3.7 bash scripts/setup_detector_env.sh cnn` |
| Sorel | `https://github.com/sophos/SOREL-20M` và implementation local `sorel_multi` | Folder local không có README; dependency nằm trong `requirements.txt` và `environment.yml`; `environment.yml` dùng Python `3.9`, PyTorch, LightGBM, `pefile`, và `git+https://github.com/elastic/ember.git` | `PYTHON_BIN=python3.9 bash scripts/setup_detector_env.sh sorel` |
| Custom XGBoost | implementation custom trong `detectors/custom_rl/xgboost` | Không phải detector upstream; dependency nằm trong `detectors/custom_rl/xgboost/requirements.txt` | `PYTHON_BIN=python3.10 bash scripts/setup_detector_env.sh custom-xgboost` |

## Artifact ngoài repository

Không có thư mục checkpoint dùng chung. Mỗi detector đọc model ở ngay trong
thư mục detector của nó; có thể đổi bằng biến môi trường tương ứng.

| Detector | Vị trí mặc định cần tự cung cấp | Biến ghi đè |
| --- | --- | --- |
| Custom detector | `detectors/custom_rl/xgboost/artifacts/binary_xgboost.joblib` | `CUSTOM_DETECTOR_MODEL_PATH` |
| Sorel | `detectors/evaluation/sorel_multi/baselines/` và `baselines/lgbm_seed1.joblib` | `SOREL_FFNN_MODEL`, `SOREL_LGBM_MODEL` |
| DeepMal | `detectors/evaluation/deep-malware-detection/assets/checkpoints/run1.pt` | `DEEPMAL_CHECKPOINT` |
| CNN | `detectors/evaluation/malware-classification-CNN/artifacts/combined_local/` | `CNN_MODEL_PATH`, `CNN_CLASS_INDICES` |
| EMBER2024 | `detectors/evaluation/EMBER2024/models/custom_multiclass.model` và `dataset_json/family_labels.json` | `EMBER_MODEL_PATH`, `EMBER_LABELS_PATH` |

Các đường dẫn trên nằm trong `.gitignore`, nên không bị đưa lên Git khi người
dùng đặt artifact vào đó. Dữ liệu RL mặc định là
`runtime/datasets/main_dataset/RL/virus` và `runtime/datasets/main_dataset/test`;
có thể đổi bằng `MALWARE_RL_TRAIN_DIR` và `MALWARE_RL_TEST_DIR`.

## Chạy custom detector với RL và STOKE

Sau khi đã đặt model custom detector và hai tập dữ liệu bên ngoài repo:

```bash
cd /path/to/TIER-Mal-Public

PYTHON_BIN=python3.7 bash scripts/setup_rl_env.sh
PYTHON_BIN=python3.9 bash scripts/setup_stoke_env.sh
PYTHON_BIN=python3.10 bash scripts/setup_detector_env.sh custom-xgboost

CUSTOM_DETECTOR_SHARED_ROOT="$PWD/runtime/share" \
  "$PWD/.venv-detector-custom-xgboost/bin/uvicorn" API:app \
  --app-dir "$PWD/detectors/custom_rl/xgboost" --host 127.0.0.1 --port 8000
```

Ở terminal khác, kiểm tra dependency và action table (17 action;
`stoke_rewrite` có index 16):

```bash
RL_PYTHON="$PWD/.venv-rl/bin/python" \
STOKE_PYTHON="$PWD/.venv-stoke/bin/python" \
MALWARE_RL_TRAIN_DIR=/path/to/RL/virus \
MALWARE_RL_TEST_DIR=/path/to/test \
bash scripts/run.sh check
```

Chạy PPO bằng cách thay `check` bằng `ppo`; có thể truyền các biến `SEED`,
`NUM_QUERIES`, `NUM_EPISODES`, `CUSTOM_DETECTOR_URL` và
`CUSTOM_DETECTOR_THRESHOLD`. STOKE chỉ xác thực functional equivalence cục bộ
qua `funcval`; không dùng hoặc khởi tạo CAPE.

## Detector đánh giá độc lập

Cài riêng từng detector theo bảng trên. `scripts/run_detector_batch.py` nhận
đường dẫn interpreter riêng cho mỗi detector, ví dụ:

```bash
SOREL_PYTHON="$PWD/.venv-detector-sorel/bin/python" \
DEEPMAL_PYTHON="$PWD/.venv-detector-deepmal/bin/python" \
python scripts/run_detector_batch.py --help
```

Trước khi đánh giá, đặt đầy đủ artifact ở bảng trên hoặc xuất các biến ghi đè.
Nếu thiếu artifact, lệnh sẽ báo đúng detector/đường dẫn thiếu thay vì tự tải.

## Kiểm tra mã không cần dữ liệu

```bash
bash -n scripts/*.sh
python -m compileall -q proposed detectors
```

`detectors/evaluation/sorel_multi/eval_sorel.py` là shell script mang đuôi
`.py`; kiểm tra file này bằng `bash -n` thay vì `compileall`.

## Lưu ý an toàn

Mã này thao tác file PE và có thể chạy trên mẫu malware. Chỉ chạy trong môi
trường cô lập, dùng mẫu được cấp phép, và không commit dataset/checkpoint/log.
