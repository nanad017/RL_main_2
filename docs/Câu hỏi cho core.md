Tôi đã đọc prompt bạn đính kèm. Nhiệm vụ của bạn là **chưa viết Methodology**, mà tạo bộ câu hỏi để bạn tự trả lời trước khi viết, theo hướng học thuật/phòng thủ/robustness evaluation, không biến thành hướng dẫn né detector thực tế . Dưới đây là bản câu hỏi theo đúng cấu trúc bạn yêu cầu.

# A. Short Literature Understanding

| Citation Key         | Source                                                                        | Main Idea                                                                                                                                      | Supports Which Methodology Part                                           | Missing Detail                                                                        |
| -------------------- | ----------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| Anderson2018         | *Learning to Evade Static PE ML Malware Models via RL*                        | Framework RL black-box cho static PE detector; agent dùng các operation bảo toàn functionality, không cần score/differentiable model           | Core Objective, Problem Formulation, Action Space, Reward, Training       | Cần kiểm tra kỹ phần empirical validation functionality vì paper cũng nêu limitations |
| MABMalware           | *MAB-Malware* / survey summary                                                | Mô hình hóa bài toán thành multi-armed bandit, dùng action-content pair, action minimization, Thompson sampling                                | Multi-Branch Action Space, Reward, State Reversion/Minimization, Baseline | Cần cite paper gốc nếu viết chi tiết thuật toán                                       |
| MERLIN               | *MERLIN*                                                                      | Dùng DQN/REINFORCE, test trên EMBER, MalConv, Grayscale, commercial AV; liên quan report vulnerability                                         | Training Procedure, Baseline, Detector Evaluation                         | Cần đọc paper gốc nếu dùng số liệu cụ thể                                             |
| MEME                 | *The Power of MEME*                                                           | Kết hợp model evasion + model extraction, dùng surrogate/model-based RL trong black-box setting                                                | Framework Overview, Query Budget, Training Procedure                      | Cần cite paper gốc khi nói surrogate/model extraction                                 |
| Zhan2024             | *Enhancing RL-based adversarial malware generation to evade static detection* | Nêu vấn đề sparse reward, dùng intrinsic curiosity reward và GAN-based action content                                                          | Reward Function, Training Procedure, Action Content                       | Cẩn thận không mô tả chi tiết payload/action content                                  |
| GAME-RL2025          | *GAME-RL*                                                                     | RL cho API-call based dynamic detection; tối ưu đồng thời insertion position và API factor; có invalid action masking, auto-regressive policy  | State Representation, Multi-Branch Action Space, Dynamic Validation       | Rất nhạy cảm nếu mô tả thao tác cụ thể; chỉ nên dùng ở mức conceptual                 |
| Kozak2024            | *Creating valid adversarial examples of malware*                              | Nhấn mạnh validity/functionality-preserving, PPO, transferability, validation của modified binaries                                            | Constraint Hierarchy, Dynamic Validation, Training, Metrics               | Cần tách rõ “validity” và “functionality”                                             |
| YanSurvey2023        | *Survey of Adversarial Attack and Defense Methods*                            | Khung Defense–Attack–Enhanced-Defense, static/dynamic, adversarial robustness, challenges như query-efficiency và inverse-mapping              | Motivation, Problem Formulation, Robustness Evaluation                    | Survey không thay thế citation gốc cho từng method                                    |
| GanGenetic2025       | *Generating Adversarial Malware Examples Against Multiple ML Detectors*       | Đánh giá nhiều detector, ASR, perturbation distance, baseline MalGAN/GAMMA/MAB                                                                 | Experiment Design, Metrics, Multi-detector robustness                     | Không phải RL chính, dùng làm nguồn về multi-detector evaluation                      |
| DynamicGANSurvey2025 | *GANs for Dynamic Malware Behavior Review*                                    | Nêu static vs dynamic behavior, sequence/tabular malware behavior, GAN/RNN/SeqGAN use cases                                                    | Dynamic Validation, Dynamic Features, Limitations                         | Không dùng làm nguồn chính cho RL                                                     |

# B. Methodology Question Bank

## 1. Core Objective

**Mục này cần làm rõ điều gì?**
Xác định framework của bạn sinh/áp dụng transformation để **đánh giá robustness của detector**, không phải trình bày như công cụ tấn công.

**Câu hỏi bắt buộc**

1. Mục tiêu chính là “tăng evasion rate” hay “đo độ bền vững của detector trước transformation có ràng buộc”?
2. Bạn đang đề xuất framework mới, cải tiến paper cũ, hay tái hiện + đánh giá lại?
3. Detector robustness được định nghĩa bằng metric nào: ASR, robust accuracy, query cost, validity rate, functionality-preserving rate, perturbation cost?
4. Contribution chính của bạn là gì: action design, reward design, validation pipeline, state reversion, multi-branch action, hay evaluation protocol?
5. Framework của bạn khác Anderson/MAB/MERLIN/MEME/Zhan2024/GAME-RL ở điểm nào?

**Câu hỏi thiết kế kỹ thuật**

1. Input là PE malware file thật, feature vector, API sequence, hay representation trừu tượng?
2. Output là transformed sample, robustness report, action sequence log, hay detector vulnerability profile?
3. Framework có tạo file executable mới không, hay chỉ mô phỏng transformation ở feature-level?
4. Bạn có giới hạn query/action/step để đảm bảo evaluation thực tế không?

**Câu hỏi citation/source**

1. Claim “RL phù hợp black-box detector” cite Anderson2018 hoặc survey.
2. Claim “malware adversarial examples cần preserve functionality” cite survey/Kozak2024.
3. Claim “query-efficiency là challenge” cite YanSurvey2023/MAB-related source.
4. Nếu bạn nói framework “mới hơn”, cần citation so sánh từng paper.

**Câu hỏi thực nghiệm**

1. Bạn sẽ đánh giá detector nào?
2. Dataset nào?
3. Baseline nào?
4. Metric nào là chính?
5. Có ablation để chứng minh contribution không?

**Rủi ro / diễn đạt an toàn**

* Tránh viết “framework giúp bypass AV”.
* Nên viết “framework stress-tests detector robustness under constrained transformations”.
* Không mô tả transformation ở mức thao tác cụ thể.

**Ưu tiên cao**

1. Mục tiêu chính là robustness hay evasion?
2. Novelty chính là gì?
3. Detector/dataset nào?
4. Metric chính là gì?
5. Phạm vi static, dynamic hay hybrid?

**Chưa trả lời thì không nên viết**

* Contribution.
* Abstract methodology.
* Claim “proposed framework outperforms”.
* Claim về robustness.

---

## 2. Problem Formulation

**Mục này cần làm rõ điều gì?**
Chuyển bài toán thành MDP/RL evaluation problem: agent, environment, state, action, reward, constraints.

**Câu hỏi bắt buộc**

1. Agent là gì?
2. Environment gồm detector + validator + transformation engine hay chỉ detector?
3. State là sample hiện tại, feature vector, action history, detector label, validation status hay kết hợp?
4. Action là transformation đơn, multi-branch action, hay action-content pair?
5. Reward được lấy từ detector label, validation result, query cost, action cost hay combined score?

**Câu hỏi thiết kế kỹ thuật**

1. Episode bắt đầu từ mẫu nào?
2. Episode kết thúc khi nào: đạt điều kiện robustness test, invalid sample, max steps, query budget, validation fail?
3. Constraint nào là hard constraint, constraint nào là soft penalty?
4. Có state reversion khi action fail không?
5. Detector là black-box hard-label hay score-based?

**Câu hỏi citation/source**

1. MDP/RL cho malware transformation: cite Anderson2018 hoặc survey.
2. Black-box hard-label setting: cite Anderson/MAB/GAME-RL.
3. Problem-space vs feature-space constraint: cite YanSurvey2023 hoặc PE adversarial survey.
4. Nếu bạn dùng multi-objective reward, cần nguồn hoặc nói rõ là đề xuất của bạn.

**Câu hỏi thực nghiệm**

1. Có query budget không?
2. Có max episode length không?
3. Có seed để tái lập không?
4. Có log action trajectory không?

**Rủi ro / diễn đạt an toàn**

* Không viết formulation như “attacker capability”.
* Nên viết “evaluation capability under controlled laboratory assumptions”.

**Ưu tiên cao**

1. MDP gồm thành phần nào?
2. Black-box hay white-box?
3. Hard-label hay score?
4. Constraint được kiểm tra ở đâu?
5. Episode termination là gì?

**Chưa trả lời thì không nên viết**

* Công thức MDP đầy đủ.
* Reward equation.
* Threat model/evaluation model.

---

## 3. Framework Overview

**Mục này cần làm rõ điều gì?**
Mô tả pipeline tổng thể ở mức module, không đi sâu thao tác malware.

**Câu hỏi bắt buộc**

1. Framework gồm những module nào: sample loader, state extractor, RL agent, action selector, transformation simulator/engine, validator, detector query, logger?
2. Luồng xử lý một episode là gì?
3. Detector query xảy ra trước hay sau validation?
4. Validation fail thì rollback, penalty hay terminate?
5. Output cuối là sample set, metric report hay robustness profile?

**Câu hỏi thiết kế kỹ thuật**

1. Có tách static validation và dynamic validation không?
2. Có cache kết quả detector/validation không?
3. Có module “state reversion” riêng không?
4. Có module “constraint hierarchy” riêng không?
5. Có figure pipeline không?

**Câu hỏi citation/source**

1. Pipeline RL malware: Anderson2018.
2. Action minimization/rewriter: MAB.
3. Validation functionality: Kozak2024/GAME-RL.
4. Dynamic behavior validation: GAME-RL có so sánh API sequence, call graph, sandbox behavior ở mức nghiên cứu .

**Câu hỏi thực nghiệm**

1. Framework log những gì?
2. Có log số query/action/invalid action không?
3. Có log validation status không?
4. Có benchmark runtime không?

**Rủi ro / diễn đạt an toàn**

* Figure chỉ nên vẽ module-level.
* Không vẽ chi tiết thao tác patch/hook/modify binary.

**Ưu tiên cao**

1. Module nào là contribution?
2. Validation nằm ở đâu?
3. Detector nằm ở đâu?
4. Reversion nằm ở đâu?
5. Output final là gì?

**Chưa trả lời thì không nên viết**

* Framework diagram.
* Algorithm overview.
* Pipeline paragraph.

---

## 4. State Representation

**Mục này cần làm rõ điều gì?**
Nêu agent quan sát gì để quyết định, nhưng không biến thành công thức bypass cụ thể.

**Câu hỏi bắt buộc**

1. State là raw bytes, PE metadata, EMBER feature vector, API sequence, action history, hay hybrid?
2. State có bao gồm detector feedback không?
3. State có bao gồm validation flags không?
4. State có bao gồm remaining query budget/action budget không?
5. State có Markov đủ không, hay cần action history?

**Câu hỏi thiết kế kỹ thuật**

1. State dimension là bao nhiêu?
2. State được normalize/encode như thế nào?
3. State có tách nhánh static/dynamic không?
4. State cập nhật sau action như thế nào?
5. Invalid state được biểu diễn thế nào?

**Câu hỏi citation/source**

1. Static feature/vector state: cite Anderson/EMBER-related source.
2. API sequence state: cite GAME-RL.
3. Reward sparsity và state exploration: cite Zhan2024.
4. Nếu state là thiết kế mới, ghi rõ “đề xuất của tôi, cần justification”.

**Câu hỏi thực nghiệm**

1. Có ablation state representation không?
2. So sánh state chỉ-static vs hybrid?
3. State có ảnh hưởng training time không?
4. State có làm leak thông tin detector không?

**Rủi ro / diễn đạt an toàn**

* Không liệt kê feature nào “dễ làm detector nhầm”.
* Chỉ mô tả state ở mức “structural / behavioral / feedback / constraint status”.

**Ưu tiên cao**

1. State gồm thành phần nào?
2. Vì sao state đủ cho agent?
3. Có action history không?
4. Có validation flag không?
5. Có budget info không?

**Chưa trả lời thì không nên viết**

* State vector equation.
* Neural encoder architecture.
* State update logic.

---

## 5. Multi-Branch Action Space

**Mục này cần làm rõ điều gì?**
Làm rõ action không phải một lựa chọn phẳng mà có nhiều nhánh: action type, location/category, content/source, constraint mode, rollback policy.

**Câu hỏi bắt buộc**

1. “Multi-branch” trong framework của bạn nghĩa là gì?
2. Các branch là action-type, action-parameter, action-content, action-location hay validation-mode?
3. Action space lấy từ paper nào hay tự thiết kế?
4. Action có chia safe/unsafe/invalid không?
5. Action có dependency/coupling không?

**Câu hỏi thiết kế kỹ thuật**

1. Agent chọn toàn bộ action một lần hay chọn theo chuỗi branch?
2. Có action masking không?
3. Có action cost không?
4. Có action minimization không?
5. Có giới hạn số action mỗi episode không?

**Câu hỏi citation/source**

1. Action-content pair và minimization: cite MAB.
2. Multi-factor/coupled action: cite GAME-RL.
3. Action-space design cải tiến qua nhiều RL methods: cite Zhan2024 table summary .
4. Nếu branch mới là của bạn, cần giải thích lý do thiết kế.

**Câu hỏi thực nghiệm**

1. Baseline action space là gì?
2. Có random action baseline không?
3. Có ablation bỏ từng branch không?
4. Có đo invalid action rate không?
5. Có đo average action length/cost không?

**Rủi ro / diễn đạt an toàn**

* Không mô tả thao tác binary cụ thể.
* Không cung cấp danh sách transformation có thể áp dụng trực tiếp.
* Viết ở mức “transformation categories constrained by validity/functionality”.

**Ưu tiên cao**

1. Branch gồm những gì?
2. Action nào được phép?
3. Action nào bị cấm?
4. Có masking không?
5. Action cost được tính không?

**Chưa trả lời thì không nên viết**

* Action table chi tiết.
* Action transition.
* Implementation notes.

---

## 6. Constraint Hierarchy

**Mục này cần làm rõ điều gì?**
Xác định constraint nào bắt buộc, constraint nào chỉ là tối ưu phụ.

**Câu hỏi bắt buộc**

1. Constraint cao nhất là parseability, loadability, executability, functionality hay safety?
2. Constraint nào kiểm tra trước detector query?
3. Constraint nào kiểm tra sau detector query?
4. Nếu action đạt detector objective nhưng làm mất functionality thì có tính success không?
5. Có phân cấp hard constraint vs soft constraint không?

**Câu hỏi thiết kế kỹ thuật**

1. Hard fail gồm lỗi nào?
2. Soft fail gồm lỗi nào?
3. Constraint penalty đưa vào reward hay terminate episode?
4. Có rollback khi vi phạm hard constraint không?
5. Có kiểm tra similarity/perturbation budget không?

**Câu hỏi citation/source**

1. Need cite cho việc malware AE phải preserve format/executability/functionality.
2. YanSurvey2023 nêu inverse-mapping và yêu cầu preserve functionality trong cyber domain .
3. Kozak2024 có trọng tâm “valid adversarial examples” và functionality-preserving modifications .

**Câu hỏi thực nghiệm**

1. Validity rate đo như thế nào?
2. Functionality preservation đo như thế nào?
3. Có báo cáo số sample bị loại vì invalid không?
4. Có timeout sandbox không?
5. Có phân tích failure cases không?

**Rủi ro / diễn đạt an toàn**

* Không mô tả cách sửa binary để vượt constraint.
* Chỉ mô tả “samples failing constraints are rejected/reverted”.

**Ưu tiên cao**

1. Hard constraint là gì?
2. Soft constraint là gì?
3. Constraint kiểm tra ở stage nào?
4. Fail xử lý thế nào?
5. Success definition có cần functionality không?

**Chưa trả lời thì không nên viết**

* Constraint hierarchy figure.
* Success criteria.
* Validity/functionality claims.

---

## 7. Reward Function

**Mục này cần làm rõ điều gì?**
Làm rõ reward đo mục tiêu robustness evaluation, không chỉ detector evasion.

**Câu hỏi bắt buộc**

1. Reward chính là detector label, detector score, robust failure indicator hay multi-objective?
2. Có reward cho validity/functionality không?
3. Có penalty cho invalid action, excessive query, excessive action cost, excessive perturbation không?
4. Reward sparse hay dense?
5. Có intrinsic reward không?

**Câu hỏi thiết kế kỹ thuật**

1. Reward tính sau mỗi action hay cuối episode?
2. Có tách extrinsic reward và intrinsic reward không?
3. Query budget penalty tuyến tính hay threshold?
4. Action cost penalty có phụ thuộc branch không?
5. Invalid sample bị reward âm, rollback hay terminate?

**Câu hỏi citation/source**

1. Basic evasion reward: cite Anderson/survey.
2. Query number/similarity as reward factors: cite Zhan2024 summary .
3. Intrinsic curiosity reward cho sparse reward: cite Zhan2024 .
4. Nếu reward của bạn có nhiều thành phần mới, cần ghi “proposed reward, no prior exact source”.

**Câu hỏi thực nghiệm**

1. Có ablation reward không?
2. So sánh sparse vs dense reward không?
3. Có learning curve không?
4. Có đo convergence không?
5. Có sensitivity với trọng số reward không?

**Rủi ro / diễn đạt an toàn**

* Không trình bày reward như công thức tối ưu bypass.
* Nên gọi là “robustness stress-test objective under safety constraints”.

**Ưu tiên cao**

1. Reward gồm thành phần nào?
2. Thành phần nào hard/soft?
3. Reward sparse hay dense?
4. Có query/action penalty không?
5. Có ablation reward không?

**Chưa trả lời thì không nên viết**

* Reward equation.
* Optimization objective.
* Claim reward cải thiện training.

---

## 8. State Reversion Mechanism

**Mục này cần làm rõ điều gì?**
Xác định khi transformation làm sample vi phạm constraint thì framework quay lại trạng thái trước như thế nào ở mức conceptual.

**Câu hỏi bắt buộc**

1. Reversion xảy ra khi validation fail, detector fail, invalid action, hay vượt budget?
2. Reversion quay lại state ngay trước action hay state gốc?
3. Reversion có kết thúc episode không?
4. Reversion khác gì “skip action”?
5. Reversion có penalty không?

**Câu hỏi thiết kế kỹ thuật**

1. Có lưu state snapshot không?
2. Có action history để undo không?
3. Có phân biệt reversible và irreversible action không?
4. Nếu nhiều action liên tiếp mới phát hiện invalid thì rollback bao nhiêu bước?
5. Reversion có cập nhật replay buffer không?

**Câu hỏi citation/source**

1. MAB action minimization có thể hỗ trợ ý tưởng loại bỏ action không cần thiết, nhưng không đồng nghĩa hoàn toàn với reversion.
2. Nếu state reversion là contribution của bạn, cần nói rõ đây là cơ chế đề xuất.
3. Cần thêm nguồn nếu muốn gọi đây là “standard mechanism”.

**Câu hỏi thực nghiệm**

1. Có đo số lần rollback không?
2. Rollback có cải thiện validity rate không?
3. Rollback có làm giảm ASR/robustness finding không?
4. Có ablation no-reversion không?
5. Có runtime overhead không?

**Rủi ro / diễn đạt an toàn**

* Không mô tả undo binary cụ thể.
* Chỉ nói “restore previous valid abstract/sample state”.

**Ưu tiên cao**

1. Khi nào rollback?
2. Rollback về đâu?
3. Có penalty không?
4. Có terminate không?
5. Đây là contribution mới hay lấy từ nguồn?

**Chưa trả lời thì không nên viết**

* Reversion algorithm.
* Reversion flowchart.
* Claim reversion bảo toàn functionality.

---

## 9. Dynamic Validation Pipeline

**Mục này cần làm rõ điều gì?**
Làm rõ pipeline kiểm tra sample transformed còn hợp lệ, còn chạy được, còn giữ hành vi mục tiêu, trước khi đưa vào robustness report.

**Câu hỏi bắt buộc**

1. Validation gồm static validation, structural validation, loadability check, dynamic sandbox check, behavior comparison, detector evaluation không?
2. Thứ tự các bước là gì?
3. Bước nào bắt buộc trước detector query?
4. Bước nào chạy sau detector query?
5. Nếu validation fail thì rollback, penalty, terminate hay loại sample?

**Câu hỏi thiết kế kỹ thuật**

1. Có sandbox không?
2. Có timeout không?
3. Có behavior signature không?
4. Có so sánh API sequence/call graph/log behavior không?
5. Có phân biệt validation nhanh và validation sâu không?

**Câu hỏi citation/source**

1. GAME-RL dùng nhiều cách functionality validation: so sánh API call sequence, function call graph, sandbox/manual behavior analysis .
2. Kozak2024 nhấn mạnh validity/functionality-preserving và đánh giá modified binaries .
3. Cần thêm nguồn riêng nếu dùng CAPE/Cuckoo cụ thể.

**Câu hỏi thực nghiệm**

1. Có báo cáo validity rate không?
2. Có báo cáo functionality-preserving rate không?
3. Có báo cáo số sample bị timeout không?
4. Có log để reproducibility không?
5. Có kiểm tra trên subset hay toàn bộ sample?

**Rủi ro / diễn đạt an toàn**

* Không viết cách làm malware chạy né sandbox.
* Không mô tả hành vi malware chi tiết.
* Chỉ nêu validation là kiểm chứng an toàn trong môi trường cô lập.

**Ưu tiên cao**

1. Validation stages là gì?
2. Stage nào hard fail?
3. Functionality check làm bằng tiêu chí nào?
4. Fail xử lý thế nào?
5. Có cite cho từng stage không?

**Chưa trả lời thì không nên viết**

* Validation pipeline.
* Experiment validity claim.
* “Functionality preserved” statement.

---

## 10. Training Procedure

**Mục này cần làm rõ điều gì?**
Nêu cách agent được train/evaluate ở mức reproducible nhưng không đủ chi tiết để lạm dụng.

**Câu hỏi bắt buộc**

1. Thuật toán RL là gì: DQN, PPO, REINFORCE, MAB, A3C, khác?
2. Vì sao chọn thuật toán đó?
3. Mỗi episode bắt đầu từ sample nào?
4. Training/test split là gì?
5. Episode kết thúc khi nào?

**Câu hỏi thiết kế kỹ thuật**

1. Exploration strategy là gì?
2. Replay buffer có dùng không?
3. Có checkpoint không?
4. Có seed không?
5. Hyperparameter nào cần báo cáo?

**Câu hỏi citation/source**

1. PPO/DQN/REINFORCE/MAB baseline: cite Anderson, MERLIN, MAB, Kozak.
2. Zhan2024 có setup dataset, split, metrics, target model, baseline, query limit để tham khảo cách trình bày thực nghiệm .
3. Nếu bạn chọn thuật toán chưa có trong paper, cần nguồn RL chung hoặc justification riêng.

**Câu hỏi thực nghiệm**

1. Baseline gồm random agent không?
2. Có baseline từ paper trước không?
3. Metric training là mean episode reward, success rate, invalid rate, query count?
4. Metric final là robust accuracy/ASR/validity/query cost?
5. Có ablation study không?

**Rủi ro / diễn đạt an toàn**

* Algorithm nên ở mức “training loop conceptual”.
* Không cung cấp pseudo-code biến đổi file.
* Không nêu parameter/action cụ thể có thể tái tạo bypass.

**Ưu tiên cao**

1. RL algorithm nào?
2. Dataset/split nào?
3. Baseline nào?
4. Episode termination?
5. Metric final?

**Chưa trả lời thì không nên viết**

* Training algorithm.
* Hyperparameter table.
* Experimental protocol.

# C. Global Questions Before Writing

1. Bạn đang tái hiện paper nào hay đề xuất framework mới?
2. Novelty chính là gì?
3. Detector là static, dynamic hay hybrid?
4. Detector là black-box hard-label, score-based, hay white-box?
5. Dataset nào?
6. Có benign set không?
7. Có malware family/time split không?
8. State gồm những gì?
9. Action space lấy từ nguồn nào?
10. Reward lấy từ nguồn nào hay tự thiết kế?
11. Constraint hierarchy gồm những tầng nào?
12. Validation pipeline gồm những bước nào?
13. Functionality được kiểm tra bằng cách nào?
14. Có query budget/action budget không?
15. Baseline gồm random, MAB, Gym-Malware, MERLIN, hoặc PPO/DQN không?
16. Metric chính là ASR hay robustness degradation?
17. Có validity rate/functionality rate không?
18. Có ablation cho reward/action/reversion/validation không?
19. Có log để tái lập không?
20. Phần nào phải viết ở mức abstraction để tránh thành hướng dẫn lạm dụng?

# D. Missing Source Checklist

* **Objective:** cần citation cho framing “robustness evaluation”, có thể dùng survey nhưng nên thêm nguồn về adversarial robustness evaluation.
* **Problem formulation:** cần cite MDP/RL malware từ Anderson2018; nếu dùng problem-space constraints nên tìm/cite nguồn gốc về problem-space adversarial examples.
* **State:** nếu dùng EMBER/raw byte/API sequence, cần cite nguồn tương ứng.
* **Action:** nếu dùng action từ paper cũ, cần cite paper gốc; nếu tự thiết kế, cần justification.
* **Reward:** nếu reward multi-objective là của bạn, ghi rõ là đề xuất; cần cite các thành phần như query cost/similarity/intrinsic reward.
* **Constraint:** cần nguồn cho parseability/loadability/executability/functionality.
* **Validation:** cần nguồn cho sandbox/behavior comparison; GAME-RL và Kozak hỗ trợ nhưng nên thêm nguồn tool/method nếu dùng cụ thể.
* **Training:** cần cite thuật toán RL và paper malware RL tương ứng.
* **Experiment:** cần nguồn cho dataset/detector/baseline.
* **Metric:** ASR, robust accuracy, perturbation distance, query count, validity rate đều cần định nghĩa rõ và citation nếu lấy từ paper.

# E. Safety and Scope Checklist

Các chỗ dễ bị viết thành hướng dẫn né detector:

1. **Action Space:** không liệt kê thao tác file cụ thể ở mức triển khai.
2. **Transformation Engine:** không mô tả cách sửa PE/binary/hook/import/section.
3. **Reward Function:** không viết như công thức tối ưu bypass thực tế.
4. **Training Procedure:** không đưa pseudo-code đủ để chạy sinh mẫu.
5. **Validation Pipeline:** không hướng dẫn chạy malware ngoài sandbox hoặc né sandbox.
6. **Detector Query:** không mô tả cách probe AV thương mại hàng loạt.
7. **Result Discussion:** dùng “robustness weakness observed under controlled evaluation”, không dùng “cách vượt qua detector”.
8. **Contribution:** framing là “defensive evaluation framework”, không phải “attack framework”.

# F. Answer Template For You

## 1. Core Objective — My Answers

1. Main objective:
2. Defensive framing:
3. Static/dynamic/hybrid scope:
4. Detector type:
5. Main contribution:
6. Difference from prior work:
7. Primary metric:
8. Source supporting this:
9. TODO:

## 2. Problem Formulation — My Answers

1. Agent:
2. Environment:
3. State:
4. Action:
5. Reward:
6. Constraint:
7. Episode termination:
8. Black-box/white-box setting:
9. Source supporting this:
10. TODO:

## 3. Framework Overview — My Answers

1. Modules:
2. Input:
3. Output:
4. Pipeline order:
5. Detector query stage:
6. Validation stage:
7. Logging:
8. Figure needed:
9. Source supporting this:
10. TODO:

## 4. State Representation — My Answers

1. State components:
2. Static features:
3. Dynamic features:
4. Action history:
5. Budget info:
6. Validation flags:
7. Encoding method:
8. Why this state is sufficient:
9. Source supporting this:
10. TODO:

## 5. Multi-Branch Action Space — My Answers

1. Branches:
2. Allowed action categories:
3. Disallowed action categories:
4. Action masking:
5. Action cost:
6. Action budget:
7. Action source paper:
8. Novel action design:
9. Source supporting this:
10. TODO:

## 6. Constraint Hierarchy — My Answers

1. Hard constraints:
2. Soft constraints:
3. Parseability check:
4. Loadability check:
5. Functionality check:
6. Similarity/perturbation check:
7. Fail handling:
8. Success definition:
9. Source supporting this:
10. TODO:

## 7. Reward Function — My Answers

1. Reward goal:
2. Detector feedback:
3. Validity reward/penalty:
4. Functionality reward/penalty:
5. Query penalty:
6. Action cost penalty:
7. Intrinsic reward:
8. Final reward formula:
9. Source supporting this:
10. TODO:

## 8. State Reversion Mechanism — My Answers

1. Trigger condition:
2. Revert target:
3. Penalty:
4. Episode termination:
5. Difference from skip action:
6. Logging:
7. Ablation:
8. Is this my contribution:
9. Source supporting this:
10. TODO:

## 9. Dynamic Validation Pipeline — My Answers

1. Static validation:
2. Structural validation:
3. Dynamic sandbox validation:
4. Behavior comparison:
5. Detector evaluation:
6. Timeout:
7. Cache/logging:
8. Fail policy:
9. Source supporting this:
10. TODO:

## 10. Training Procedure — My Answers

1. RL algorithm:
2. Reason for choosing:
3. Training samples:
4. Test samples:
5. Episode start:
6. Episode end:
7. Exploration:
8. Baselines:
9. Metrics:
10. Hyperparameters:
11. Seed/reproducibility:
12. Source supporting this:
13. TODO:
