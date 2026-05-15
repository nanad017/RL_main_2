# Custom Target Mode

Tai lieu nay ghi lai cach da them mode `custom` vao du an de RL query detector cua ban qua API.

## Muc tieu

Mode `custom` duoc them de:

- dung detector chinh do ban tu train lam oracle that
- van giu observation dang vector 2381 chieu theo feature extractor EMBER
- van chay duoc pipeline `ppo_model_extract.py`
- van train surrogate bang pipeline `ember` de khong phai viet surrogate rieng ngay

## Cac file da them/sua

### File moi

- `malware_rl/envs/utils/custom_api.py`
  - dinh nghia `CustomAPIModel`
  - ghi PE da sua vao shared folder
  - goi `POST /score` den detector API
  - doc `score` tu JSON response

- `malware_rl/envs/custom_gym.py`
  - dinh nghia `CustomDetectorEnv`
  - dung detector API lam target that
  - luu `observations.npy` va `scores.npy` vao `data/memory/custom`

- `docs/custom_mode/README.md`
  - tai lieu nay

### File da sua

- `malware_rl/__init__.py`
  - dang ky `custom-train-v0`
  - dang ky `custom-test-v0`
  - doc bien moi truong:
    - `CUSTOM_DETECTOR_URL`
    - `CUSTOM_DETECTOR_SHARED_ROOT`
    - `CUSTOM_DETECTOR_THRESHOLD`
  - doi `entry_point` sang module cu the de tranh import day chuyen

- `malware_rl/envs/__init__.py`
  - bo import tat ca env o top-level de tranh bat buoc nap `sorel.model`

- `ppo_model_extract.py`
  - them `custom` vao CLI choices
  - dang ky surrogate env bang `malware_rl.envs.lgb_gym:LGBEnv`

- `ppo.py`
  - them `custom` vao CLI choices

- `random_agent.py`
  - them `custom` vao CLI choices

- `surrogate.py`
  - cho `target == "custom"` dung chung nhanh voi `ember`
  - bo `shap` khoi flow chay chinh
  - doi `SorelFFNN` sang lazy import

- `malware_rl/envs/controls/modifier.py`
  - them guard/fallback cho mot so action de rollout khong crash khi benign PE parse loi

## Flow cua custom mode

1. RL env lay sample PE tu `malware_rl/envs/utils/samples/`
2. Action modifier sua binary
3. `CustomDetectorEnv` goi `CustomAPIModel.predict_sample(bytez, sha256)`
4. `CustomAPIModel` ghi file vao:
   - `CUSTOM_DETECTOR_SHARED_ROOT/rl_scoring/<sha256>`
5. `CustomAPIModel` goi API:

```json
{
  "relative_path": "rl_scoring/<sha256>"
}
```

6. API detector cua ban:
   - doc file tu `SHARED_ROOT / relative_path`
   - extract feature
   - chay `predict_proba`
   - tra ve JSON co field `score`
7. Env lay `score` ve de:
   - tinh reward
   - quyet dinh evade thanh cong neu `score < threshold`

## API contract

Code custom hien tai mong API co:

- `POST /score`
- request JSON:

```json
{
  "relative_path": "rl_scoring/sample_name.exe"
}
```

- response JSON:

```json
{
  "score": 0.8732,
  "path": "/some/absolute/path",
  "relative_path": "rl_scoring/sample_name.exe"
}
```

Code RL chi dung `payload["score"]`.

## Bien moi truong can set

Neu API cua ban dang dung:

```python
SHARED_ROOT = Path("/home/rl/RL/MAB-malware/data/share").resolve()
```

thi can set:

```bash
export CUSTOM_DETECTOR_URL="http://127.0.0.1:8000"
export CUSTOM_DETECTOR_SHARED_ROOT="/home/rl/RL/MAB-malware/data/share"
export CUSTOM_DETECTOR_THRESHOLD="0.5"
```

`CUSTOM_DETECTOR_SHARED_ROOT` phai trung voi `SHARED_ROOT` cua API.

## Cach chay

### 1. Kich hoat env Python

```bash
source .venv37_clean/bin/activate
```

### 2. Chay detector API

Vi du:

```bash
uvicorn app:app --host 0.0.0.0 --port 8000
```

### 3. Set bien moi truong

```bash
export CUSTOM_DETECTOR_URL="http://127.0.0.1:8000"
export CUSTOM_DETECTOR_SHARED_ROOT="/home/rl/RL/MAB-malware/data/share"
export CUSTOM_DETECTOR_THRESHOLD="0.5"
```

### 4. Chay RL extraction

```bash
python ppo_model_extract.py --target custom --seed 39720
```

### 5. Chay thu nhanh

Random agent:

```bash
python random_agent.py --target custom --seed 39720
```

PPO don gian:

```bash
python ppo.py --target custom --seed 39720 --num-queries 4096
```

## Luu y quan trong

- `custom` hien tai chi thay detector chinh
- surrogate cua `custom` van reuse pipeline `ember`
- vi vay mode nay van can:
  - package Python `ember`
  - file `malware_rl/envs/utils/ember_model.txt`
  - dataset EMBER tai duong dan hard-code trong `surrogate.py`

## Cac warning da gap va y nghia

- `is not a valid DLL name/import name and will be discarded`
  - PE da bi meo mot phan sau modification

- `Relocation corrupted: BlockSize is out of bound...`
  - bang relocation bi hong sau khi sua PE

- `Error while parsing the signature`
  - chu ky so/certificate parse khong duoc

Nhung warning tren thuong khong lam dung harn pipeline neu code van tiep tuc in:

- `Sample: ...`
- `Episode over: reward = ...`

## Huong cai tien sau nay

Neu can lam sach hon, buoc tiep theo nen la:

- viet surrogate rieng cho detector `custom`
- bo phu thuoc `ember` trong `surrogate.py`
- cho API nhan file truc tiep thay vi thong qua shared folder
