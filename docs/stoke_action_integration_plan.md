# Kế hoạch tích hợp action `stoke` (STOKE rewrite) qua worker Python 3.9

> Tài liệu này dành cho **một AI coding agent khác** thực thi trên máy triển khai.
> Nó đã được viết lại **bám sát repo thật** (`D:\model\meme_main`, package `malware_rl`),
> không phải hướng dẫn chung chung. Đọc kỹ phần "Trạng thái hiện tại" trước khi sửa.

---

## 0. TÓM TẮT QUAN TRỌNG NHẤT (đọc trước)

**Action `stoke` KHÔNG cần tích hợp từ đầu — nó ĐÃ tồn tại trong repo dưới tên `stoke_rewrite`.**

- Đã có trong `ACTION_TABLE` (tier 3), đã được tất cả 7 gym env expose qua `action_space`.
- Đã có method `ModifyBinary.stoke_rewrite()` và helper `get_stoke_command()`.
- Cơ chế dispatch, reward theo tier, checkpoint compatibility **đã hoạt động**.

**Việc thực sự cần làm = THAY BACKEND của `stoke_rewrite`**, từ:

> (cũ) gọi 1 binary `STOKE_REWRITER_CLI input.exe output.exe`, không có n/seed/rewrites,
> validate bằng `lief.PE.parse`, cho phép đổi size.

sang:

> (mới) gọi **worker Python 3.9** chạy package `stoke_actions`, truyền `--n --seed --rewrites`,
> giao tiếp **JSON qua stdout**, validate **size phải bằng input**, fallback an toàn về bytes gốc.

Không đổi tên action, không đổi thứ tự `ACTION_TABLE`, không đổi gym, không đổi reward. Chỉ:
1. **Thêm mới** 1 file worker Python 3.9.
2. **Thêm mới** 1 file bridge Python 3.7 (`stoke_bridge.py`).
3. **Sửa** 2 hàm trong `modifier.py` (`stoke_rewrite` + `get_stoke_command`) để gọi bridge.
4. (Tùy chọn) thêm test.

---

## 1. TRẠNG THÁI HIỆN TẠI CỦA REPO (đã verify bằng đọc code)

### 1.1. Dispatch action — cơ chế

File trung tâm: **`malware_rl/envs/controls/modifier.py`**

- `ACTION_TABLE` (dict, dòng ~493): keys là tên action. Thứ tự dict = thứ tự index action.
  `stoke_rewrite` là **entry CUỐI CÙNG** (tier 3).
- `ACTION_TIER` (dòng ~517): `"stoke_rewrite": 3`. `NUM_TIERS = 3`.
- `modify_sample(bytez, action)` (dòng ~484):
  ```python
  def modify_sample(bytez, action):
      bytez = ModifyBinary(bytez).__getattribute__(action)()
      return bytez
  ```
  → gọi method cùng tên action trên `ModifyBinary`. Input `bytes`, output `bytes`.

### 1.2. Các env (7 file gym) — đều CÙNG pattern

`malware_rl/envs/{custom,malconv,sorel,sorelFFNN,ember,lgb,AV}_gym.py`:
```python
from malware_rl.envs.controls import modifier
ACTION_LOOKUP = {i: act for i, act in enumerate(modifier.ACTION_TABLE.keys())}
...
self.action_space = spaces.Discrete(len(ACTION_LOOKUP))
...
# trong _take_action():
action = ACTION_LOOKUP[int(action_ix)]
self.bytez = modifier.modify_sample(self.bytez, action)
```

→ **Vì `stoke_rewrite` đã có trong `ACTION_TABLE`, action space của mọi env đã bao gồm nó.
KHÔNG được chạm vào 7 file gym này.**

### 1.3. Implementation hiện tại của `stoke_rewrite` (sẽ bị thay)

Trong `modifier.py` (dòng ~426–481):

```python
def stoke_rewrite(self):
    stoke_cmd = get_stoke_command()        # đọc env STOKE_REWRITER_CLI hoặc binary local
    if stoke_cmd is None:
        return self.bytez
    # ... ghi input.exe, subprocess.run(stoke_cmd + [input_pe, output_pe], timeout=120)
    # ... nếu rc==0 & output tồn tại & lief.PE.parse OK → nhận candidate
    # ... finally: xóa tmp dir

def get_stoke_command():
    raw = os.environ.get("STOKE_REWRITER_CLI")   # split shell, kiểm tra tồn tại
    # fallback: <repo>/../stoke_workspace/stoke_rewriter (binary)
```

**Vấn đề so với yêu cầu mới:** không truyền `n/seed/rewrites`, không dùng package
`stoke_actions`, không có giao thức JSON, không enforce size-equal, contract env var khác.

### 1.4. Reward — không cần đụng

`malware_rl/envs/reward.py` dùng `ACTION_TIER` + `NUM_TIERS`. Giữ `stoke_rewrite` ở tier 3 là đủ.

### 1.5. Ràng buộc Python version

- Core/env chạy **Python 3.7**. Bridge phải tương thích 3.7 (đã ok: chỉ dùng
  `subprocess`, `tempfile`, `os`, `json`, `pathlib`).
- Package `stoke_actions` chỉ chạy **Python 3.9** → cô lập hoàn toàn trong worker.
- **TUYỆT ĐỐI không** `import stoke_actions` ở bất kỳ file nào core 3.7 chạm tới
  (modifier.py, stoke_bridge.py). Chỉ worker được import.

---

## 2. KIẾN TRÚC: subprocess (giữ nguyên, không dùng HTTP)

Repo đã dùng pattern subprocess (`stoke_rewrite` cũ, `inject_call`). Mỗi env step gọi action
một lần, không cần throughput cao → **subprocess là đúng**, ít xâm lấn, không cần lifecycle
service, dễ debug. **Không** dựng HTTP service.

Luồng mới:

```
Python 3.7 env.step(action_ix)
  → ACTION_LOOKUP[ix] == "stoke_rewrite"
  → modify_sample → ModifyBinary.stoke_rewrite()
  → stoke_bridge.apply_stoke_action(self.bytez, ...)        [3.7, chỉ subprocess]
     → ghi temp input.exe
     → subprocess.run([STOKE_PYTHON, STOKE_WORKER, --input ... --output ... --n --seed --rewrites])
        → worker (3.9) đọc input.exe
        → import stoke_actions; out = sa.mutate(pe, n=, seed=, rewrites=)
        → validate bytes & size==input
        → ghi output.exe; in JSON {"ok":true,...} ra stdout
     → bridge đọc JSON dòng cuối; validate ok / file tồn tại / size==input
     → đọc output bytes
  → trả mutated bytes về env (size không đổi)
  → pipeline detector/feature/reward tiếp tục như mọi action khác
```

Mọi lỗi (timeout, rc≠0, JSON hỏng, thiếu file, size lệch, exception) → **trả lại bytes gốc**,
không bao giờ crash RL loop.

---

## 3. HỢP ĐỒNG GIAO TIẾP (interface contract)

### 3.1. Bridge (Python 3.7 side)

```python
def apply_stoke_action(pe_bytes, seed=None, n=8, rewrites="proven_v3_cleaned", timeout=60) -> bytes
```
- Input không phải bytes/bytearray → trả nguyên input.
- Luôn trả `bytes`. Lỗi bất kỳ → trả `pe_bytes` gốc (size không đổi).

### 3.2. Worker (Python 3.9 side) — CLI

```
<STOKE_PYTHON> <STOKE_WORKER> --input IN.exe --output OUT.exe --n 8 --seed 123 --rewrites proven_v3_cleaned
```
- `--input` (bắt buộc): path PE gốc.
- `--output` (bắt buộc): path PE đã mutate.
- `--n` (int, default 8): số mutation tối đa.
- `--seed` (int, optional): để reproducible; nếu không truyền → để stoke_actions tự random.
- `--rewrites` (str, default `proven_v3_cleaned`).

**stdout: đúng 1 dòng JSON cuối cùng.**
- Thành công: `{"ok": true, "input_size": N, "output_size": N, "changed": true|false}` exit 0.
- Lỗi: `{"ok": false, "error": "msg"}` exit ≠ 0.

### 3.3. Biến môi trường (config — không hardcode)

| Env var          | Ý nghĩa                                   | Default khi thiếu                                  |
| ---------------- | ----------------------------------------- | -------------------------------------------------- |
| `STOKE_PYTHON`   | Path tới Python 3.9 (venv/conda)          | `"python3.9"` (PATH)                               |
| `STOKE_WORKER`   | Path tới `stoke_worker.py`                | resolve relative cạnh `modifier.py`                |
| `STOKE_N`        | (tùy chọn) override n                     | 8                                                  |
| `STOKE_REWRITES` | (tùy chọn) override rewrites              | `proven_v3_cleaned`                                |
| `STOKE_TIMEOUT`  | (tùy chọn) timeout giây                   | 60                                                 |
| `STOKE_SEED`     | (tùy chọn) seed cố định                   | None (random mỗi lần)                              |

> Lưu ý: env var cũ `STOKE_REWRITER_CLI` **không còn dùng** ở backend mới. Có thể xóa
> `get_stoke_command()` cũ hoặc giữ lại nhưng không gọi (xem mục 4.3). Khuyến nghị xóa để
> tránh nhầm lẫn.

---

## 4. CÁC THAY ĐỔI CỤ THỂ THEO FILE

### 4.1. THÊM MỚI — `malware_rl/envs/controls/stoke_worker.py` (chạy bằng Python 3.9)

```python
#!/usr/bin/env python3
"""STOKE worker — CHẠY BẰNG PYTHON 3.9 ONLY. Không import từ core 3.7.
Đọc PE input, mutate .text bằng stoke_actions, ghi output cùng size, in JSON status."""
import argparse
import json
import sys
from pathlib import Path


def emit(obj, code=0):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()
    sys.exit(code)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--n", type=int, default=8)
    p.add_argument("--seed", type=int, default=None)
    p.add_argument("--rewrites", default="proven_v3_cleaned")
    args = p.parse_args()

    try:
        import stoke_actions as sa

        pe = Path(args.input).read_bytes()
        if not pe:
            emit({"ok": False, "error": "empty input"}, code=2)

        mutated = sa.mutate(pe, n=args.n, seed=args.seed, rewrites=args.rewrites)

        if not isinstance(mutated, (bytes, bytearray)):
            emit({"ok": False, "error": "stoke returned non-bytes"}, code=3)
        mutated = bytes(mutated)

        if len(mutated) != len(pe):
            emit({"ok": False, "error": "size changed",
                  "input_size": len(pe), "output_size": len(mutated)}, code=4)

        Path(args.output).write_bytes(mutated)
        emit({"ok": True, "input_size": len(pe),
              "output_size": len(mutated), "changed": mutated != pe}, code=0)

    except Exception as e:
        emit({"ok": False, "error": repr(e)}, code=1)


if __name__ == "__main__":
    main()
```

> Đặt cạnh `modifier.py` để bridge resolve path dễ. Worker **không** import gì từ `malware_rl`.

### 4.2. THÊM MỚI — `malware_rl/envs/controls/stoke_bridge.py` (Python 3.7-compatible)

```python
"""Bridge 3.7 → worker 3.9. CHỈ subprocess. KHÔNG import stoke_actions ở đây."""
import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_N = 8
DEFAULT_REWRITES = "proven_v3_cleaned"
DEFAULT_TIMEOUT = 60

_WORKER_DEFAULT = str(Path(__file__).resolve().parent / "stoke_worker.py")


def _fail(original, reason):
    logger.warning("stoke action fallback: %s", reason)
    return original


def apply_stoke_action(pe_bytes, seed=None, n=None, rewrites=None, timeout=None):
    if not isinstance(pe_bytes, (bytes, bytearray)):
        return pe_bytes
    original = bytes(pe_bytes)

    stoke_python = os.environ.get("STOKE_PYTHON", "python3.9")
    worker_path = os.environ.get("STOKE_WORKER", _WORKER_DEFAULT)

    if n is None:
        n = int(os.environ.get("STOKE_N", DEFAULT_N))
    if rewrites is None:
        rewrites = os.environ.get("STOKE_REWRITES", DEFAULT_REWRITES)
    if timeout is None:
        timeout = float(os.environ.get("STOKE_TIMEOUT", DEFAULT_TIMEOUT))
    if seed is None and os.environ.get("STOKE_SEED"):
        seed = int(os.environ["STOKE_SEED"])

    if not os.path.isfile(worker_path):
        return _fail(original, "worker not found: %s" % worker_path)

    try:
        with tempfile.TemporaryDirectory(prefix="stoke_action_") as td:
            td = Path(td)
            in_path = td / "input.exe"
            out_path = td / "output.exe"
            in_path.write_bytes(original)

            cmd = [stoke_python, worker_path,
                   "--input", str(in_path), "--output", str(out_path),
                   "--n", str(int(n)), "--rewrites", str(rewrites)]
            if seed is not None:
                cmd += ["--seed", str(int(seed))]

            proc = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=timeout, universal_newlines=True,
            )
            if proc.returncode != 0:
                return _fail(original, "rc=%s err=%s" % (proc.returncode, (proc.stderr or "")[:200]))

            lines = (proc.stdout or "").strip().splitlines()
            if not lines:
                return _fail(original, "no stdout")
            try:
                status = json.loads(lines[-1])
            except Exception:
                return _fail(original, "bad json: %r" % lines[-1][:200])
            if not status.get("ok"):
                return _fail(original, "worker ok=false: %s" % status.get("error"))

            if not out_path.exists():
                return _fail(original, "no output file")
            mutated = out_path.read_bytes()
            if not mutated:
                return _fail(original, "empty output")
            if len(mutated) != len(original):
                return _fail(original, "size mismatch %d!=%d" % (len(mutated), len(original)))
            return mutated
    except subprocess.TimeoutExpired:
        return _fail(original, "timeout")
    except Exception as e:
        return _fail(original, "exception: %r" % e)
```

> Ghi chú Windows: `tempfile.TemporaryDirectory` đôi khi không xóa được nếu worker còn giữ
> handle — đã tránh vì worker đóng file ngay. Nếu deploy trên Linux (theo các path
> `/home/rl/...` trong handoff) thì không vấn đề.

### 4.3. SỬA — `malware_rl/envs/controls/modifier.py`

**(a)** Thêm import (đầu file, cùng cụm import controls):
```python
from .stoke_bridge import apply_stoke_action as _apply_stoke_action
```

**(b)** Thay thân method `stoke_rewrite` (dòng ~426–466) thành thin wrapper:
```python
def stoke_rewrite(self):
    """Rewrite .text bằng STOKE qua worker Python 3.9 (xem stoke_bridge).
    Output cùng size; lỗi bất kỳ → giữ nguyên bytes gốc."""
    self.bytez = _apply_stoke_action(self.bytez)
    return self.bytez
```

**(c)** Xóa hàm `get_stoke_command()` (dòng ~469–481) và import không còn dùng nếu chỉ phục
vụ nó (`shlex`; kiểm tra `shutil`/`subprocess` còn dùng chỗ khác trước khi xóa — **giữ lại**
nếu còn dùng). Nếu muốn an toàn, có thể giữ `get_stoke_command()` nhưng không gọi nữa.

**KHÔNG đổi:** `ACTION_TABLE` (giữ key `stoke_rewrite` ở cuối), `ACTION_TIER`, `NUM_TIERS`,
`modify_sample`. → action space & checkpoint index giữ nguyên.

### 4.4. KHÔNG SỬA

- 7 file `*_gym.py` (action space tự động đúng).
- `reward.py`.
- Bất kỳ logic detector/feature/reset/dataset nào.

---

## 5. CHUẨN BỊ MÔI TRƯỜNG PYTHON 3.9

### Venv (Linux — khớp handoff path)
```bash
python3.9 -m venv ~/venvs/stoke39
source ~/venvs/stoke39/bin/activate
pip install /home/rl/stoke_workspace/stoke_actions_handoff/stoke_actions-0.1.0-py3-none-any.whl
pip install "/home/rl/stoke_workspace/stoke_actions_handoff/stoke_actions-0.1.0-py3-none-any.whl[disasm]"
python -c "import stoke_actions as sa; print(sa.__version__)"
```
Lấy path python rồi export cho shell chạy project 3.7:
```bash
export STOKE_PYTHON=$HOME/venvs/stoke39/bin/python
export STOKE_WORKER=/path/to/repo/malware_rl/envs/controls/stoke_worker.py
```

### Conda (nếu đã có env)
```bash
conda activate sorel-malware-detector   # hoặc env có stoke_actions
python -c "import stoke_actions as sa; print(sa.__version__)"
which python    # → dùng làm STOKE_PYTHON
export STOKE_PYTHON=/path/to/conda/env/bin/python
export STOKE_WORKER=/path/to/repo/malware_rl/envs/controls/stoke_worker.py
```

### Windows (nếu deploy trên máy Windows này)
```powershell
$env:STOKE_PYTHON = "C:\path\to\py39\python.exe"
$env:STOKE_WORKER = "D:\model\meme_main\malware_rl\envs\controls\stoke_worker.py"
```

---

## 6. KIỂM THỬ (theo thứ tự)

**Test 1 — Worker độc lập (env 3.9):**
```bash
$STOKE_PYTHON $STOKE_WORKER --input sample.exe --output /tmp/out.exe --n 8 --seed 1 --rewrites proven_v3_cleaned
```
Kỳ vọng: exit 0; stdout JSON `"ok": true`; file output tồn tại; `input_size == output_size`.

**Test 2 — Bridge (env 3.7):**
```python
from malware_rl.envs.controls.stoke_bridge import apply_stoke_action
b = open("sample.exe","rb").read()
out = apply_stoke_action(b, seed=1)
assert isinstance(out, bytes) and len(out) == len(b)
```
Kỳ vọng: bytes, size không đổi. Set `STOKE_PYTHON` sai → trả đúng `b`, không crash.

**Test 3 — Action dispatch:**
```python
from malware_rl.envs.controls import modifier
assert "stoke_rewrite" in modifier.ACTION_TABLE
out = modifier.modify_sample(open("sample.exe","rb").read(), "stoke_rewrite")
assert isinstance(out, bytes)
```

**Test 4 — End-to-end env step:** chạy 1 episode nhỏ, ép action index = index của
`stoke_rewrite` (= `len(ACTION_TABLE)-1`), xác nhận env không crash, các action cũ vẫn chạy,
sample đi qua detector/reward như cũ.

**Test 5 — Failure cases (đều phải fallback bytes gốc, không crash):**
`STOKE_PYTHON` sai · `STOKE_WORKER` sai · `STOKE_TIMEOUT=0.001` · input rỗng/non-PE garbage.

> Có thể thêm test vào `run_tests.py` theo style hiện có (xem `test_inject_via_modifier_action`,
> dùng sample trong `SAMPLES_DIR`). Test bridge nên mock/skip nếu môi trường CI không có 3.9.

---

## 7. CHECKLIST BÁO CÁO SAU KHI SỬA

1. File đã đọc để xác định dispatch: `modifier.py`, 7 `*_gym.py`, `reward.py`, `run_tests.py`.
2. File sửa: `malware_rl/envs/controls/modifier.py` (chỉ `stoke_rewrite` + bỏ `get_stoke_command`).
3. File thêm mới: `stoke_worker.py`, `stoke_bridge.py` (cùng thư mục `controls/`); (tùy chọn) test.
4. Action hook: tái dùng entry `stoke_rewrite` có sẵn trong `ACTION_TABLE` (tier 3, index cuối) — không đổi action space.
5. Luồng chạy mới: xem mục 2.
6. Cách chuẩn bị env 3.9 + export `STOKE_PYTHON`/`STOKE_WORKER`: mục 5.
7. Lệnh test đầy đủ: mục 6.

---

## 8. QUY TẮC BẤT BIẾN

- Không nâng project lên 3.9; không sửa system Python; không `import stoke_actions` ở core 3.7.
- Không đổi tên action (`stoke_rewrite`), không đổi thứ tự/độ dài `ACTION_TABLE` (giữ checkpoint compat).
- Không refactor lớn; không đổi detector/reward/reset/dataset/các action khác.
- `stoke` lỗi → fallback bytes gốc; tuyệt đối không crash training loop.
- Output phải **cùng size** input (đặc tính của `stoke_actions`); size lệch = coi như fail.
