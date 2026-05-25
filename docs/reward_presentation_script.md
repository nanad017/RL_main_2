# Kịch bản trình bày: Tier-Aware Reward Design

---

## SLIDE 0: Bảng ký hiệu — Giải thích tất cả symbols

**Nói:**

"Trước tiên em liệt kê hết các ký hiệu sẽ xuất hiện trong bài trình bày, anh coi qua để khi vào công thức mình không bị ngắt."

### Ký hiệu chung

| Ký hiệu | Đọc là | Ý nghĩa | Ví dụ |
|---|---|---|---|
| $r(t)$ | "r tại t" | Tổng reward mà agent nhận ở bước thứ $t$ | $r(3) = 8.8 - 0.04 + 1.0$ |
| $t$ | "t" | Số bước hiện tại trong episode (bắt đầu từ 1) | $t = 3$ nghĩa là agent đã thực hiện 3 action |
| $T_{max}$ | "T max" | Số bước tối đa cho phép trong 1 episode | $T_{max} = 5$ → agent có tối đa 5 lần thử |
| $f(s_t)$ | "f của s tại t" | Điểm malicious mà detector trả về ở bước $t$. Càng cao = càng bị nghi malware | $f(s_0) = 0.92$ → detector 92% tin đây là malware |
| $f(s_0)$ | "f của s zero" | Điểm malicious ban đầu (chưa mutation) | $f(s_0) = 0.92$ |
| $\tau$ | "tau" | Ngưỡng phát hiện (threshold). Nếu $f(s_t) < \tau$ → evade thành công | EMBER: $\tau = 0.8336$, SOREL: $\tau = 0.5$ |
| $B_0$ | "B zero" | Binary gốc (chưa bị sửa) | File malware.exe ban đầu |
| $B_t$ | "B tại t" | Binary sau $t$ bước mutation | File đã bị sửa qua 3 action |
| $|B_t|$ | "size B tại t" | Kích thước (bytes) của binary ở bước $t$ | $|B_0| = 50\text{KB}$, $|B_3| = 51\text{KB}$ |

### Ký hiệu hệ số (hyperparameters)

| Ký hiệu | Đọc là | Ý nghĩa | Giá trị mặc định | Tại sao chọn giá trị này |
|---|---|---|---|---|
| $R_b$ | "R bonus" | Phần thưởng cố định khi evade thành công | 10.0 | Giữ tương thích với MEME gốc để dễ so sánh fair |
| $\lambda_q$ | "lambda q" (q = query) | Hệ số phạt khi evade chậm. Càng lớn → càng khắc nghiệt với evade muộn | 0.3 | Ở $\lambda_q = 0.3$: step cuối vẫn được 7.0 điểm (không quá khắc nghiệt), step đầu được 10.0 → chênh lệch 3.0 đủ cho PPO học |
| $\lambda_s$ | "lambda s" (s = size) | Hệ số phạt khi file phình to. Càng lớn → càng phạt nặng file bloat | 2.0 | 1 lần pad_overlay (+100KB trên file 50KB = 200%) → penalty = -4.0, đủ lớn để cân bằng với score-diff thường khoảng +0.1 |
| $\lambda_d$ | "lambda d" (d = diversity) | Hệ số thưởng khi dùng đa dạng tier. Càng lớn → càng ép agent thử nhiều loại | 1.0 | Max bonus = +1.0 khi dùng cả 3 tier, chỉ đóng vai tie-breaker khi 2 chiến lược cho R_score tương đương |
| $\lambda_f$ | "lambda f" (f = functional) | Hệ số phạt khi binary bị vỡ chức năng cốt lõi. Cố ý đặt > $R_b$ để penalty luôn override evasion reward | 15.0 | Nặng hơn R_bonus (10): dù agent evade thành công, nếu binary không chạy được → tổng vẫn âm. Đủ để PPO học tuyệt đối không phá functionality |

### Ký hiệu tier

| Ký hiệu | Đọc là | Ý nghĩa |
|---|---|---|
| $\mathcal{T}_{used}$ | "T used" | Tập hợp các tier mà agent đã dùng trong episode hiện tại |
| $\mathcal{T}_{all}$ | "T all" | Tập hợp tất cả tier có thể = {1, 2, 3} |
| $|\mathcal{T}_{used}|$ | "số phần tử T used" | Số tier đã dùng (1, 2, hoặc 3) |
| $|\mathcal{T}_{all}|$ | Luôn = 3 | Tổng số tier |
| Tier 1 | "Tier một" | Structural mutations — đổi header, overlay, section (13 actions) |
| Tier 2 | "Tier hai" | API surface — thêm API benign, hook API suspicious (2 actions) |
| Tier 3 | "Tier ba" | Code rewrite — STOKE superoptimizer viết lại .text section (1 action) |

### Ký hiệu kiểm tra chức năng

| Ký hiệu | Đọc là | Ý nghĩa |
|---|---|---|
| $\mathbb{1}_{broken}$ | "indicator broken" | = 1 nếu binary mất chức năng cốt lõi sau mutation; = 0 nếu vẫn chạy được |
| $check\_func(B_t)$ | "check func B tại t" | Hàm kiểm tra chức năng: trả về True nếu binary còn chạy được, False nếu bị vỡ. **Hiện tại: chưa triển khai, mặc định trả về True** |

---

### Công thức đầy đủ với chú thích từng phần

```
r(t) = R_score(t) + R_size(t) + R_tier(t) + R_func(t)
       ─────────   ─────────   ─────────   ─────────
          ①            ②          ③            ④

① R_score(t) = ┌ R_b × (1 - λ_q × (t-1)/T_max)    nếu f(s_t) < τ     ← EVADE
               │
               └ f(s_0) - f(s_t)                     nếu chưa evade     ← SHAPING
                 ────────  ──────
                 score gốc  score hiện tại
                 (cố định)  (thay đổi mỗi step)

② R_size(t) = -λ_s × max(0, (|B_t| - |B_0|) / |B_0|)
                           ─────────────────────────
                           tỉ lệ file phình so với gốc
                           (= 0 nếu file nhỏ hơn hoặc bằng gốc)

③ R_tier(T) = λ_d × |T_used| / |T_all|              ← CHỈ tính ở cuối episode
                     ─────────  ───────
                     số tier     luôn = 3
                     đã dùng

④ R_func(t) = -λ_f × 𝟙_broken(B_t)                 ← -15.0 nếu binary bị vỡ, 0 nếu còn chạy được
              ──────  ──────────────
              hệ số    indicator: 1 nếu broken, 0 nếu OK
              phạt
              (> R_b)

  ⚠️  CHƯA TRIỂN KHAI: check_func(B_t) hiện tại luôn trả về True
      → 𝟙_broken = 0 → R_func = 0 (không ảnh hưởng training cho đến khi implement)
```

**Đọc thành lời:**

"Reward bằng: phần thưởng score CỘng phần phạt kích thước CỘng phần thưởng đa dạng TRỪ phần phạt chức năng.

- Phần score: nếu evade được thì thưởng 10 nhân với hệ số hiệu quả (evade sớm → hệ số cao hơn). Nếu chưa evade thì thưởng bằng mức giảm score so với ban đầu.
- Phần size: trừ điểm tỉ lệ thuận với mức file phình to. File không phình → không bị trừ.
- Phần tier: cộng thêm điểm nếu agent dùng nhiều loại action khác nhau. Chỉ cộng 1 lần ở cuối episode.
- Phần func: phạt nặng -15 nếu binary mất chức năng cốt lõi. Nặng hơn cả evasion reward (10) để PPO học tuyệt đối không phá binary. Hiện tại chưa có checker nên mặc định = 0."

---

## SLIDE 1: Vấn đề của reward cũ

**Mở đầu:**

"Anh ơi, trước khi em trình bày reward mới, em muốn chỉ ra 3 vấn đề của reward hiện tại mà MEME gốc và các bài khác đang dùng."

**Nói:**

Tất cả các bài hiện tại — MEME, MAB-malware, GAME-RL — đều tính reward rất đơn giản:

```
Evade thành công → thưởng 10 điểm
Chưa evade       → original_score - current_score (hoặc 0)
```

Cách này có **4 vấn đề thực tế**:

1. **Không phân biệt evade nhanh hay chậm.** Evade ở step 1 hay step 10 đều được 10 điểm như nhau. Agent không có động lực tìm chiến lược ngắn gọn hơn.

2. **Không kiểm soát kích thước file.** Mỗi lần gọi `pad_overlay` là thêm ~100KB. Sau 5 bước overlay, file phình thêm 500KB — bản thân kích thước bất thường đó đã là một tín hiệu phát hiện malware. Nhưng reward cũ không phạt điều này.

3. **Agent chỉ xài 1-2 action quen thuộc.** Vì tất cả action cho cùng reward, agent sẽ converge vào vài action "an toàn" (thường là overlay append), không bao giờ thử API-level hay code-rewrite — dù những action đó có thể hiệu quả hơn với detector cụ thể.

4. **Không kiểm soát tính hợp lệ của binary.** Một số mutation (đặc biệt section rewrite, stoke) có thể làm hỏng PE header hoặc phá luồng thực thi. Reward cũ vẫn thưởng 10 điểm dù binary không còn chạy được — agent học ra pattern evasion vô nghĩa.

---

## SLIDE 2: Reward mới — 3 thành phần

**Nói:**

"Em thiết kế reward mới gồm 4 thành phần, mỗi thành phần giải quyết đúng 1 vấn đề ở trên."

```
r(t) = R_score + R_size + R_tier + R_func
```

### Thành phần 1: R_score — Thưởng có trọng số hiệu quả

**Giải quyết vấn đề 1: evade nhanh hay chậm đều như nhau**

```
Nếu evade thành công:
    R_score = 10 × (1 - 0.3 × (t-1) / T_max)

Nếu chưa evade:
    R_score = original_score - current_score
```

**Ví dụ cụ thể** (T_max = 5 bước):

| Evade ở step | Tính toán | R_score |
|---|---|---|
| Step 1 | 10 × (1 - 0.3 × 0/5) | **10.0** |
| Step 2 | 10 × (1 - 0.3 × 1/5) | **9.4** |
| Step 3 | 10 × (1 - 0.3 × 2/5) | **8.8** |
| Step 5 | 10 × (1 - 0.3 × 4/5) | **7.6** |

→ Agent được thưởng nhiều hơn khi tìm ra chiến lược evade ít bước. Chênh lệch 2.4 điểm giữa step 1 và step 5 là đủ lớn để PPO học được.

→ Phần score-diff (`original - current`) vẫn giữ nguyên cho các bước chưa evade, đảm bảo agent có gradient signal liên tục.

---

### Thành phần 2: R_size — Phạt phình file

**Giải quyết vấn đề 2: file bị bloat không kiểm soát**

```
R_size = -2.0 × max(0, (size_hiện_tại - size_gốc) / size_gốc)
```

**Ví dụ cụ thể** (file gốc 50KB):

| Sau action | Size hiện tại | Tỉ lệ phình | R_size |
|---|---|---|---|
| rename_section | 50KB (+0) | 0% | **0.0** (không phạt) |
| add_api_group | 50.5KB (+0.5KB) | 1% | **-0.02** (gần như 0) |
| pad_overlay | 150KB (+100KB) | 200% | **-4.0** (phạt nặng!) |
| 3× overlay | 350KB (+300KB) | 600% | **-12.0** (phạt rất nặng) |

→ Action Tier 2 (API) và Tier 3 (stoke) hầu như không thay đổi size → không bị phạt.
→ Action Tier 1 (overlay, section) bị phạt tỉ lệ thuận với mức phình → agent phải cân nhắc.
→ Agent học được: "nếu đã dùng 1 overlay, đừng spam thêm, thử API hoặc stoke."

---

### Thành phần 3: R_tier — Thưởng đa dạng chiến lược

**Giải quyết vấn đề 3: agent chỉ xài 1-2 action**

```
R_tier = 1.0 × (số tier đã dùng / 3)     ← chỉ tính ở cuối episode
```

Mình có 3 tier:
- **Tier 1**: Structural (13 actions) — đổi header, overlay, section
- **Tier 2**: API surface (2 actions) — thêm API benign, hook API suspicious  
- **Tier 3**: Code rewrite (1 action) — STOKE superoptimizer

**Ví dụ cụ thể:**

| Chiến lược agent chọn | Tiers used | R_tier |
|---|---|---|
| Chỉ dùng overlay + rename | {1} → 1/3 | **+0.33** |
| Overlay + add_api_group | {1, 2} → 2/3 | **+0.67** |
| Overlay + iat_patch + stoke | {1, 2, 3} → 3/3 | **+1.00** |

→ Agent được thưởng thêm khi phối hợp nhiều bề mặt tấn công.
→ Bonus +1.0 tuy nhỏ so với R_score (10), nhưng đủ để PPO ưu tiên chiến lược đa dạng khi 2 chiến lược cho R_score tương đương.

---

### Thành phần 4: R_func — Phạt vỡ chức năng cốt lõi

**Giải quyết vấn đề 4: binary bị hỏng mà agent không bị phạt**

```
R_func(t) = -λ_f × 𝟙_broken(B_t)
          = -15.0   nếu check_func(B_t) == False   ← binary không chạy được
          =   0.0   nếu check_func(B_t) == True    ← binary còn nguyên
```

**Tại sao λ_f = 15.0 (lớn hơn R_bonus = 10)?**

Nếu λ_f ≤ R_b, agent có thể "chấp nhận đánh đổi": evade được (+10) dù binary bị hỏng (−10) → tổng = 0, agent không học được gì. Đặt λ_f = 15 đảm bảo:

| Kịch bản | R_score | R_func | Tổng |
|---|---|---|---|
| Evade + binary OK | +10 | 0 | **+10** (tốt) |
| Evade + binary broken | +10 | −15 | **−5** (vẫn tệ) |
| Không evade + binary broken | ~0 | −15 | **−15** (rất tệ) |

→ Agent học: evade mà phá binary còn tệ hơn không evade gì cả.

**⚠️ Trạng thái hiện tại — chưa triển khai:**

```python
def check_func(binary: bytes) -> bool:
    # TODO: chưa triển khai
    # Tùy chọn: sandbox execution, PE header validation, import table check...
    return True   # ← mặc định: luôn coi binary là còn chạy được
                  #   → R_func = 0 trong toàn bộ training hiện tại
```

Khi triển khai xong, chỉ cần thay dòng `return True` bằng logic kiểm tra thực, không cần đổi công thức reward.

---

## SLIDE 3: Ví dụ tổng hợp — So sánh 2 episode

**Nói:**

"Em cho anh thấy 2 episode cụ thể để thấy reward mới khác reward cũ như thế nào."

**Episode A — Agent chỉ spam overlay (chiến lược cũ):**

| Step | Action | Score | Size |
|---|---|---|---|
| 0 | — | 0.92 | 50KB |
| 1 | pad_overlay | 0.85 | 150KB |
| 2 | pad_overlay | 0.78 | 250KB |
| 3 | pad_overlay | 0.71 | 350KB |
| 4 | pad_overlay | 0.55 | 450KB |
| 5 | pad_overlay | **0.42** ✓ evade | 550KB |

Reward cũ: **10.0**
Reward mới:
- R_score = 10 × (1 - 0.3 × 4/5) = **7.6**
- R_size = -2.0 × (550-50)/50 = **-20.0**
- R_tier = 1.0 × 1/3 = **+0.33**
- R_func = 0 *(default — chưa có checker)*
- **Tổng = -12.07** ← bị phạt dù evade thành công!

**Episode B — Agent phối hợp 3 tier:**

| Step | Action | Score | Size |
|---|---|---|---|
| 0 | — | 0.92 | 50KB |
| 1 | add_api_group (Tier 2) | 0.78 | 50.5KB |
| 2 | iat_patch_api (Tier 2) | 0.55 | 51KB |
| 3 | stoke_rewrite (Tier 3) | **0.38** ✓ evade | 51KB |

Reward cũ: **10.0** (giống hệt Episode A!)
Reward mới:
- R_score = 10 × (1 - 0.3 × 2/5) = **8.8**
- R_size = -2.0 × (51-50)/50 = **-0.04**
- R_tier = 1.0 × 3/3 = **+1.0**
- R_func = 0 *(default — chưa có checker)*
- **Tổng = +9.76** ← thưởng cao!

**Episode C — Giả định khi R_func được triển khai (stoke phá PE header):**

| Step | Action | Score | Size | Binary OK? |
|---|---|---|---|---|
| 1 | pad_overlay (Tier 1) | 0.72 | 150KB | ✓ |
| 2 | stoke_rewrite (Tier 3) | **0.35** ✓ evade | 150KB | ✗ broken |

Reward mới (khi checker hoạt động):
- R_score = 10 × (1 - 0.3 × 1/5) = **9.4**
- R_size = -2.0 × (150-50)/50 = **-4.0**
- R_tier = 1.0 × 2/3 = **+0.67**
- R_func = -15.0 × 1 = **-15.0**
- **Tổng = -8.93** ← evade nhưng binary hỏng → bị phạt nặng

**Kết luận từ ví dụ:**

| | Reward cũ | Reward mới (hiện tại) | Reward mới (khi có checker) |
|---|---|---|---|
| Episode A (spam overlay) | 10.0 | **-12.07** | **-12.07** |
| Episode B (hybrid 3 tier, binary OK) | 10.0 | **+9.76** | **+9.76** |
| Episode C (evade nhưng binary hỏng) | 10.0 | **+9.76** *(không phân biệt được)* | **-8.93** |

→ Reward mới đã tạo gradient rõ ràng giữa A và B. Khi triển khai checker, C sẽ bị phân biệt khỏi B.

---

## SLIDE 4: So sánh với các bài khác

**Nói:**

"Bây giờ em đặt reward của mình cạnh các bài khác để anh thấy novelty."

| | MAB-malware | GAME-RL | MEME gốc | **Của mình** |
|---|---|---|---|---|
| Loại reward | Binary (Beta-Binomial) | Sparse (10 hoặc 0) | Score-diff + bonus 10 | **4-component shaped** |
| Query efficiency | Không | Có (ω₁) nhưng tắt | Không | **Có (λ_q = 0.3)** |
| Size penalty | Không | Không | Không | **Có (λ_s = 2.0)** |
| Action diversity | Không | Không | Không | **Có (λ_d = 1.0)** |
| Functional integrity | Không | Không | Không | **Có (λ_f = 15.0)** *(default = 0, chờ implement)* |
| Intermediate signal | Deferred | Không | Có | **Có** |

→ **Size regularization, tier-diversity incentive, và functional integrity penalty** đều chưa thấy trong reward design của các bài PE evasion RL hiện tại.

---

## SLIDE 5: Tại sao chọn các hệ số này?

**Nói (nếu sếp hỏi):**

| Hệ số | Giá trị | Lý do |
|---|---|---|
| R_bonus = 10 | Giữ nguyên | Tương thích với MEME gốc, dễ so sánh |
| λ_q = 0.3 | 0.3 | Step cuối vẫn được 7.0 (không quá khắc nghiệt) |
| λ_s = 2.0 | 2.0 | 1 overlay (100KB/50KB = 200%) → penalty -4.0, đủ mạnh để cân bằng với score-diff |
| λ_d = 1.0 | 1.0 | Dùng cả 3 tier → +1.0, là tie-breaker khi R_score tương đương |
| λ_f = 15.0 | 15.0 | Lớn hơn R_bonus: evade + broken vẫn cho tổng âm → agent không thể exploit |

Tất cả hệ số đều tunable qua constructor `TierAwareReward(lambda_q=..., lambda_s=..., lambda_d=..., lambda_f=...)`. Em có thể chạy ablation study bằng cách tắt từng thành phần.

---

## SLIDE 6: Kết — 1 câu tóm tắt

**Nói:**

"Tóm lại: reward cũ coi mọi kiểu evade đều như nhau. Reward mới dạy agent 4 điều:

1. **Evade nhanh** tốt hơn evade chậm.
2. **File nhỏ** tốt hơn file phình.
3. **Phối hợp nhiều loại action** tốt hơn spam 1 loại.
4. **Giữ nguyên chức năng binary** là điều kiện tiên quyết — evade mà binary hỏng không được tính.

Điều 2, 3, 4 đều chưa thấy trong reward design của các bài PE evasion RL hiện tại. Điều 4 hiện tại đang ở default = 0 (chờ triển khai checker), nhưng kiến trúc reward đã sẵn sàng."

---

## CÂU HỎI DỰ PHÒNG

**Q: "Lambda_s = 2.0 có quá lớn không? File overlay sẽ luôn bị phạt?"**

A: Đúng, overlay bị phạt nặng — đó là mục đích. Trong thực tế, file malware 50KB mà phình lên 550KB sẽ bị flagged bởi heuristic rule trước khi đến ML detector. Size penalty buộc agent tìm cách khác hiệu quả hơn. Nếu muốn nới, giảm λ_s xuống 0.5-1.0.

**Q: "R_tier có bị exploit không? Agent cứ gọi 1 action mỗi tier rồi xong?"**

A: R_tier chỉ là +1.0 max, trong khi R_score là 7-10 điểm. Agent không thể "cheat" bằng cách gọi action vô nghĩa — nếu action không giảm score, R_score bị âm, lỗ nhiều hơn +0.33. R_tier chỉ là tie-breaker.

**Q: "Sao không dùng reward riêng cho từng action?"**

A: Per-action reward cần domain knowledge quá sâu (action nào "đáng" bao nhiêu điểm?). Tier-based reward giữ tổng quát hơn — chỉ cần phân loại action vào 3 tier, không cần gán giá trị cho từng action.

**Q: "R_func chưa implement — vậy có ý nghĩa gì khi trình bày bây giờ?"**

A: Hai lý do: (1) Kiến trúc reward đã tính đến thành phần này ngay từ đầu — khi checker được viết xong chỉ cần plug in, không phải redesign reward. (2) Khi trình bày design, việc thừa nhận một thành phần "đã thiết kế nhưng chưa chạy được" minh bạch hơn là bỏ qua hẳn. Tôi đang đánh giá các phương án checker: sandbox execution, PE header validation, hay import table integrity check.

**Q: "check_func sẽ implement bằng cách nào?"**

A: 3 hướng theo độ phức tạp tăng dần:
1. **PE header validation** (nhanh, nhẹ): dùng `pefile` kiểm tra header/section table còn hợp lệ không. Không cần chạy binary.
2. **Import table check** (trung bình): kiểm tra tất cả DLL/function được import vẫn resolve được. Phát hiện được các lỗi từ stoke_rewrite hoặc iat_patch sai.
3. **Sandbox execution** (chính xác nhất, nặng nhất): chạy binary trong sandbox (Wine/cuckoo), kiểm tra exit code hoặc side effect. Tốn thời gian nhất nhưng ground truth thực sự.

Hiện tại plan là bắt đầu từ hướng 1-2, đủ cho mục đích training.

**Q: "Ablation study cần chạy gì?"**

A: 5 experiment:
1. Full reward (baseline)
2. Tắt R_size (λ_s = 0) → đo ảnh hưởng size penalty
3. Tắt R_tier (λ_d = 0) → đo ảnh hưởng diversity bonus
4. Tắt R_score efficiency (λ_q = 0) → đo ảnh hưởng query scaling
5. Bật R_func (λ_f = 15, khi checker sẵn sàng) → đo tỉ lệ binary bị hỏng giảm bao nhiêu

Mỗi experiment chạy trên cùng dataset, so sánh evasion rate + avg file size + avg episode length + tier distribution + binary validity rate.
