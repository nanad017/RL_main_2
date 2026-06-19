# Kế hoạch refactor: gắn `funcval` vào reward pipeline RL + STOKE

> Cập nhật 2026-06-19: triển khai cả CAPE behavioral path trong STOKE worker
> theo API `verify_async()` / `collect_async()`. CAPE được bật mặc định bởi
> `scripts/run_custom_detector_with_stoke.sh` (`FUNCVAL_CAPE_ENABLED=1`). Khi
> chưa có calibration, behavioral evidence chỉ là diagnostic và không được tự
> ý vượt qua `funcval.admit()`; sync `Refuted` luôn chiếm ưu thế.

## Vấn đề hiện tại

Pipeline RL hiện tại có action `stoke_rewrite` trong action table. Khi PPO chọn action này, STOKE sẽ rewrite bytes trong PE, sau đó PE đã mutate được đưa qua custom detector để chấm điểm. Reward pipeline đã có sẵn hook kiểm tra functional integrity qua `TierAwareReward.check_func`, nhưng hiện tại hook này vẫn là placeholder mặc định và luôn trả về `True`.

Nói ngắn gọn: agent có thể nhận reward tốt từ detector cho một mutation do STOKE tạo ra, kể cả khi đoạn instruction bị rewrite chưa được kiểm chứng là giữ nguyên chức năng.

Mục tiêu của refactor này là dùng `funcval` để kiểm tra các cặp rewrite của STOKE, rồi đưa kết quả pass/fail đó vào reward component `R_func`. Nếu `funcval` fail, unknown, hoặc thiếu metadata bắt buộc, reward phải bị phạt đủ mạnh để mutation đó không còn “có lời” với agent.

Ràng buộc quan trọng nhất: `funcval` chỉ được kiểm tra instruction fragment, không được đưa nguyên file `.exe` vào `verify_sync`. Hiện tại `stoke_worker.py` chỉ trả về whole PE đã mutate và JSON status đơn giản; nó chưa trả về metadata cấp instruction như `orig_bytes` và `mut_bytes`.

## Hướng giải quyết

Thêm một đường dữ liệu mới cho mutation result. Đường cũ `modify_sample()` vẫn giữ nguyên và vẫn trả về `bytes`, để không phá các caller hiện tại. Đường mới sẽ trả về cả bytes sau mutation và metadata đi kèm, ví dụ action name, bytes có thay đổi không, và verdict của `funcval`.

`funcval` nên chạy trong STOKE worker, tức môi trường Python của STOKE, không chạy trực tiếp trong RL runtime Python 3.7. Lý do là máy kia đã cài `stoke_actions` và `funcval` trong env:

```bash
/home/rl/miniconda3/envs/sorel-malware-detector/bin/python
```

Worker sẽ gọi STOKE để tạo rewrite. Khi có được cặp instruction:

```python
orig_bytes, mut_bytes
```

worker sẽ gọi:

```python
ev = validator.verify_sync(orig_bytes, mut_bytes, bits=bits)
funcval_pass = admit(ev, alpha=0.05)
```

Sau đó worker trả verdict dạng JSON-safe về RL runtime. Reward không import `funcval`; reward chỉ đọc verdict đã được worker tạo.

Chính sách ban đầu nên là reward shaping, chưa hard reject. Nghĩa là mutation vẫn đi qua pipeline, detector vẫn có thể chấm điểm, nhưng nếu `funcval` fail thì `R_func` bị trừ. Với config hiện tại `DEFAULT_LAMBDA_F = 15.0`, penalty này đủ mạnh để một STOKE rewrite fail không có lợi, kể cả nếu detector bị né.

Hard gate có thể thêm sau bằng env flag, nhưng không nên là bước đầu tiên.

## Các commit nhỏ đề xuất

1. Thêm data model cho mutation result.

   Tạo một object nhỏ biểu diễn kết quả mutation. Nó cần chứa PE bytes cuối cùng, action name, cờ bytes có thay đổi hay không, và metadata kiểm tra functional nếu có. Commit này chưa đổi behavior.

2. Thêm API mutation mới trả metadata.

   Giữ `modify_sample()` như cũ để trả raw bytes. Thêm một entrypoint mới, ví dụ kiểu `modify_sample_with_report()`, trả mutation result. Nhờ vậy env có thể dùng metadata mới, còn code cũ vẫn chạy bình thường.

3. Đưa `stoke_rewrite` đi qua đường report-bearing.

   Mở rộng STOKE bridge để có một function mới trả cả mutated bytes và worker status đã parse. Function cũ vẫn trả bytes. Nếu worker lỗi, timeout, JSON lỗi, size mismatch, hoặc không có output file, bridge trả về original bytes kèm report giải thích fallback.

4. Mở rộng JSON status của STOKE worker.

   Worker cần trả thêm các field ổn định: action outcome, PE bitness nếu detect được, mutation có đổi bytes không, `funcval` có được chạy không, và lý do nếu skip/fail. Commit này vẫn phải chạy được khi chưa cài `funcval`.

5. Thêm adapter lấy metadata rewrite từ STOKE.

   Trên máy đã cài STOKE, kiểm tra `stoke_actions` có thể trả gì ngoài whole PE mutated. Nếu nó trả trực tiếp rewrite pairs thì dùng luôn. Nếu nó chỉ trả whole PE, cần thêm hoặc dùng helper phía STOKE để expose instruction-level rewrite pairs. Không được suy ra cặp hợp lệ bằng cách diff nguyên file PE.

6. Detect đúng PE bitness ở phía STOKE worker.

   Worker phải phân biệt 32-bit và 64-bit từ PE header hoặc metadata đáng tin cậy của STOKE. PE32 dùng `bits=32`, PE32+ dùng `bits=64`. Nếu không detect được bitness thì đánh dấu `funcval` fail/skip có lý do, không được mặc định bừa là 64-bit.

7. Thêm wrapper chạy `funcval` trong worker.

   Trong worker-side runtime, import `FunctionValidator` và `admit`. Tạo validator một lần trong process, tránh tạo lại cho từng mutation. Với mỗi rewrite pair, gọi `verify_sync()` theo đúng bitness.

8. Chuẩn hóa verdict của `funcval` thành JSON metadata.

   Trả về verdict gọn gồm: pass/fail, kind, false-admit bound nếu có, bitness, đoạn `orig_hex` ngắn, đoạn `mut_hex` ngắn, và reason nếu fail/skip. Không bao giờ log hoặc trả full PE bytes trong JSON.

9. Thêm config policy cho `funcval`.

   Thêm env vars để cấu hình alpha, có require funcval cho STOKE không, có yêu cầu proof recheckable không, và fail thì phạt reward hay hard gate. Default ban đầu nên là:

   ```text
   alpha = 0.05
   require funcval cho changed STOKE rewrite = true
   pass bonus = 0.0
   fail penalty = dùng R_func
   hard gate = false
   ```

10. Mở rộng input của reward bằng action-level functional context.

   `TierAwareReward.__call__` hiện đã nhận `binary`. Thêm optional context để truyền action name và functional-check metadata. Phải giữ tương thích với tests/callers cũ chỉ truyền binary.

11. Implement checker đọc verdict của `funcval`.

   Checker mới sẽ:

   - trả `True` cho non-STOKE actions
   - trả `True` cho `stoke_rewrite` có verdict admitted/pass
   - trả `False` cho `stoke_rewrite` fail, unknown, missing required, skipped required

   Checker này không import `funcval`; nó chỉ đọc verdict JSON-safe từ worker.

12. Wire các Gym env để truyền mutation report vào reward.

   Trong các env `step()`, thay vì chỉ gọi mutation API bytes-only, gọi API mới có report. Env update `self.bytez` từ result, rồi truyền report vào reward context. Episode history có thể giữ nguyên, chỉ thêm diagnostic nếu cần.

13. Thêm logging tập trung cho `funcval`.

   Mỗi lần action `stoke_rewrite` được check, log một dòng gọn gồm:

   ```text
   action=stoke_rewrite
   bits=32/64
   funcval_kind=...
   false_admit_bound=...
   funcval_pass=True/False
   orig_hex=<short>
   mut_hex=<short>
   reason=...
   ```

   Không log full binary hoặc buffer quá dài.

14. Update script `run_custom_detector_with_stoke.sh check`.

   Mode `check` hiện đã kiểm `stoke_actions`. Mở rộng thêm kiểm tra import:

   ```python
   import funcval
   from funcval import FunctionValidator, admit
   ```

   Nếu config yêu cầu `funcval` thì thiếu `funcval` phải fail sớm. Nếu đang chạy mode không require thì có thể chỉ warning.

15. Thêm unit tests cho reward compatibility.

   Test default reward không đổi khi không có functional metadata. Test STOKE verdict pass không bị phạt. Test fail, unknown, missing required, checker exception đều tạo functional penalty và vẫn giữ return contract `(float, bool)`.

16. Thêm tests cho mutation-result compatibility.

   Test API cũ vẫn trả bytes. Test API mới trả cùng bytes cộng metadata. Test fallback khi STOKE worker missing vẫn trả original bytes và report rõ lý do.

17. Thêm STOKE bridge tests bằng fake worker.

   Fake worker nên cover các case: success + funcval pass, success + funcval fail, missing metadata, invalid JSON, timeout. Bridge không được crash RL process trong bất kỳ case nào.

18. Thêm worker-side tests chạy trên máy có STOKE.

   Thêm hoặc document test chạy bằng `STOKE_PYTHON` để kiểm smoke case thật:

   ```python
   bytes.fromhex("85c0")
   bytes.fromhex("21c0")
   bits=32
   ```

   Test này có thể skip ở máy local nếu chưa có `funcval`, nhưng phải pass trên máy triển khai.

19. Update tài liệu cách chạy.

   Bổ sung vào `cách chay.md` phần kiểm tra `funcval` và log kỳ vọng. Flow chạy chính vẫn giữ nguyên: start custom detector, chạy script `check`, chạy `TRAIN_ONLY=1 ... meme`, rồi evaluate checkpoint.

20. Validate trên máy đích.

   Trên máy đã cài môi trường đầy đủ, chạy theo thứ tự:

   ```bash
   bash scripts/run_custom_detector_with_stoke.sh check
   python -m pytest malware_rl/envs/controls/test_stoke_bridge.py -q
   python -m pytest tests_reward -q
   TRAIN_ONLY=1 bash scripts/run_custom_detector_with_stoke.sh meme
   ```

   Xác nhận log có:

   ```text
   stoke_rewrite
   funcval_kind=...
   funcval_pass=True/False
   ```

## Quyết định kỹ thuật

- STOKE worker là boundary cho các dependency không tương thích với RL runtime Python 3.7.
- RL runtime không import `funcval` trực tiếp.
- `funcval` chỉ kiểm instruction fragment, không kiểm whole PE.
- Metadata rewrite phải lấy từ STOKE hoặc helper phía STOKE, không tự dựng bằng whole-file diff.
- API mutation cũ vẫn giữ để tương thích ngược.
- Env step sẽ dùng API mới có metadata để reward biết action context.
- Reward hook `check_func`/`R_func` là nơi chính thức xử lý functional failure.
- Policy ban đầu là penalty-based reward shaping, chưa hard reject.
- `Unknown`, `Refuted`, behavioral uncalibrated, bound vượt alpha, hoặc missing required đều coi là fail.
- Bitness phải detect đúng theo từng sample/rewrite; không được mặc định 64-bit.
- Flow custom detector và `TRAIN_ONLY=1` giữ nguyên.

## Quyết định testing

- Test tốt nên kiểm behavior nhìn thấy từ bên ngoài: fallback mutation, reward value, env step contract, JSON contract của worker, và script prerequisite.
- Không test chi tiết private implementation của validator wrapper, trừ phần cần thiết để ổn định JSON contract.
- Tests reward hiện có là prior art cho compatibility và penalty behavior.
- Tests STOKE bridge hiện có là prior art cho missing-worker fallback và same-size mutation.
- Tests bytecode-swap hiện có là prior art cho action-level mutation smoke test trên PE thật.
- Real `funcval` tests có thể skip ở máy thiếu STOKE env, nhưng phải chạy trên máy đích đã cài đủ.

## Ngoài phạm vi

- Không cài `funcval`, STOKE, CAPE, hoặc conda env trong repo này.
- Không đổi custom detector API hoặc cách detector tính score.
- Không chỉnh PPO hyperparameters, action-space ordering, hoặc surrogate training.
- Không chứng minh whole-program PE semantic equivalence.
- Không dùng behavioral/CAPE result làm reward online nếu chưa calibrate.
- Không dựng rewrite pair từ arbitrary PE diff.

## Ghi chú thêm

- Việc đầu tiên cần xác minh trên máy kia là `stoke_actions` có expose được `orig_bytes`/`mut_bytes` hay không. Đây là nút thắt chính.
- Nếu chưa lấy được metadata instruction-level ngay, vẫn có thể wire checker/reward trước, nhưng changed `stoke_rewrite` nên fail-closed khi `funcval` là required. Như vậy agent không được reward detector cho mutation chưa kiểm chứng.
- Sau khi implement, cách chạy vẫn theo `cách chay.md`: start custom detector, chạy `scripts/run_custom_detector_with_stoke.sh check`, chạy train-only MEME, rồi evaluate checkpoint.
