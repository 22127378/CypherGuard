# Báo cáo phiên làm việc — 27/11/2026

**Chủ đề:** Sửa các vấn đề cấu hình còn tồn đọng từ phiên 26/11, deploy lại từ đầu lên AWS và kiểm thử đầy đủ cả hai chế độ detect và prevent
**Thời lượng lab chạy:** khoảng 3 giờ (04:30–07:35 UTC)
**Kết quả:** Giải quyết dứt điểm vấn đề mất alert, Active Response lần đầu cô lập đúng container trên hạ tầng thật, tìm và sửa thêm 10 lỗi (#10–#19), lab đã destroy sạch

---

## 1. Bối cảnh

Phiên 26/11 kết thúc với một vấn đề chưa giải quyết ([báo cáo 26/11](session-report-2026-11-26.md), mục 4): pipeline Falco → Wazuh mất khoảng 4/5 alert, agent hay bị "Disconnected" sau khi restart manager, và Active Response chưa lần nào cô lập được container. Mục tiêu hôm nay:

1. Tìm nguyên nhân và sửa offline trước, để không tốn tiền debug trên cluster.
2. Deploy lại **từ state trống**, chưa lần nào làm kể từ khi sửa lỗi #4 hôm qua.
3. Đo lại tỷ lệ mất alert bằng một bài test lặp lại được.
4. Chạy đủ chế độ prevent: admission, chuỗi tấn công, Active Response, GuardDuty → Lambda.

## 2. Diễn biến chính

### 2.1. Sửa offline (trước khi deploy)

Chạy một event Falco qua `wazuh-analysisd` thật (container `wazuh-manager:4.14.10`) cho thấy Wazuh **tách key có dấu chấm thành object lồng nhau** khi xuất alert: `container.id` thành `{"container": {"id": ...}}`. Script Active Response tìm key phẳng nên luôn nhận về rỗng, khớp chính xác với dòng log "no pod container id" thấy hôm qua. Sửa thêm hai điểm cấu hình nhắm vào việc agent mất kết nối: `apply.sh` chỉ restart manager khi cấu hình thật sự đổi, và `logcollector` đọc tiếp các dòng ghi ra trong lúc agent reconnect (`only-future-events=no`).

### 2.2. Deploy từ đầu — lỗi ngay ở bước plan

`terraform apply` trên state trống fail với "Invalid count argument" (**lỗi #10**). Fix #4 hôm qua (`enable_bootstrap_user_data`) đưa IP của Wazuh vào user data của node, mà IP này chỉ biết sau khi tạo instance. Hôm qua không lộ ra vì instance Wazuh đã tồn tại sẵn. Sửa bằng cách gán cho Wazuh một IP private cố định tính từ CIDR của VPC (`10.20.0.10`). Lần apply thứ hai tạo đủ 104 resource, và agent enroll được ngay từ lần boot đầu.

Bước `wazuh-sync` đầu tiên fail vì chính bản sửa sáng nay (**lỗi #11**): hàm fingerprint đọc một file chưa tồn tại trên manager mới, và `set -e` cùng `pipefail` dừng script. Sửa xong, chạy lại thì thành công, và lần sync thứ hai xác nhận không restart manager khi cấu hình không đổi.

### 2.3. Chế độ detect

- Smoke test **11/11**, gồm IRSA gọi SSM thật.
- Chuỗi tấn công (`measure-latency.sh`): **10/10 rule đạt target**, gồm rule tương quan exfiltration mã hóa (level 14).
- Bài test delivery mới (`scripts/delivery-test.sh`) đếm số event Falco ghi ra và số alert Wazuh nhận được:

| Lượt | Falco | Wazuh |
|---|---|---|
| 20 lần, cách nhau 3s | 20 | **20** |
| 30 lần liên tục | 30 | **30** |
| 20 lần, restart manager giữa chừng | 20 | **20** |

### 2.4. Tìm ra nguyên nhân gốc thật sự (chế độ prevent, lượt 1)

Khi bật Active Response, container không bị kill và agent lại "Disconnected". Lần này lab đang chạy nên điều tra trực tiếp được trên node (qua một pod privileged trong `kube-system`, vì node không có SSM):

- `wazuh-agentd` treo trong `sock_alloc_send_pskb`, `last_ack` đứng yên, không có kết nối TCP nào tới cổng 1514 dù cổng vẫn mở.
- Process `cat` con của script Active Response đã chạy **5 phút** mà không thoát.

**Nguyên nhân (lỗi #12):** script đọc stdin bằng `$(cat)`, tức là chờ EOF, nhưng `wazuh-execd` 4.x ghi một dòng JSON rồi **giữ pipe mở**. Script treo, execd ngừng đọc hàng đợi, agentd bị block khi chuyển tiếp lệnh cho execd, nên ngừng gửi keepalive và event. Đây là nguyên nhân chung của cả ba triệu chứng hôm qua: agent "Disconnected", mất alert, và Active Response không chạy.

Cùng lúc phát hiện **lỗi #13**, nghiêm trọng: rule IMDS (100113) bắt cả `aws-node` (VPC CNI, chạy hostNetwork và gọi IMDS liên tục), tạo ra khoảng **1.400 alert CRITICAL** trong 30 phút. Một lệnh Active Response bị treo, được giải phóng khi agent restart, đã **kill nhầm `aws-node`**. Mình tắt Active Response ngay, rồi sửa hai lớp: rule Falco loại `kube-system`, và script chỉ được hành động trong namespace `demo`.

Sau khi sửa, Active Response chạy nhưng container vẫn sống (**lỗi #14**): `ctr tasks kill` mặc định gửi SIGTERM, mà app là PID 1 trong namespace và không cài handler, nên kernel bỏ qua tín hiệu. Đổi sang SIGKILL: container bị kill khoảng 1 giây sau khi kích hoạt (exit 137), và Kubernetes khởi động lại.

**Lỗi #15:** `wazuh-sync` báo fail dù thật ra đã chạy xong, vì `aws ssm wait` bỏ cuộc sau khoảng 100s trong khi `apply.sh` chờ agent tới 2 phút. Đổi sang polling.

### 2.5. Chế độ prevent, lượt đầy đủ

- Smoke test enforce **11/11**. Cả 4 test admission (image chưa ký từ registry lạ, pod privileged, hostPath `/`, cluster-admin cho ServiceAccount) đều bị chặn.
- Lượt chạy chuỗi tấn công đầu tiên không tấn công được gì (**lỗi #19**): các script chọn pod đầu tiên trong danh sách, mà lúc đó là pod đã bị evict.
- Chạy lại thì chuỗi bị chặn ở mọi bước (xem bảng mục 4).
- **Lỗi #16:** chạy `/tmp/kill -TERM falco` chỉ báo rule "Exec From Writable Temp", không báo "Kill Security Agent". Falco 0.45 mặc định `rule_matching: first`, nên mỗi event chỉ khớp một rule. Kẻ tấn công thả công cụ vào `/tmp` sẽ che được rule nghiêm trọng hơn. Đổi sang `rule_matching: all`, và Active Response kill container sau 2 giây.

### 2.6. Phía cloud

- **GuardDuty → Lambda (gọi trực tiếp):** một finding nhắm vào role `cipherguard-demo-app` khiến Lambda gắn policy Deny-all. Lần gọi SSM tiếp theo của pod bị từ chối với thông báo *"explicit deny in an identity-based policy"*.
- **GuardDuty → EventBridge → Lambda (tự động):** sample finding kích hoạt Lambda, nhưng Lambda **crash**. Đọc code thì thấy **lỗi #17**, nghiêm trọng: nhánh vô hiệu hóa access key **không có giới hạn phạm vi**. Một finding mức cao, kể cả false positive, nêu tên bất kỳ IAM user nào cũng sẽ khiến key của user đó bị vô hiệu hóa, kể cả user vận hành `cipherguard-admin`. Ngoài ra, mọi IAM user tên `cipherguard-*` còn bị xử lý nhầm như role. Sau khi sửa và deploy lại Lambda, sample finding được bỏ qua an toàn trong khoảng 14 giây.
- **Lỗi #18:** chưa có finding GuardDuty nào tới được Wazuh kể từ khi tích hợp, vì role của Wazuh chỉ có quyền đọc log group của EKS. Mỗi lần poll đều bị `AccessDenied`. Thêm quyền đọc `/cipherguard/guardduty` thì rule 100312 báo đúng.
- **CloudTrail:** alert 100300 cho hai lệnh `AccessDenied` ở bước 3 tới sau 12,5 phút (target 15 phút).

### 2.7. Destroy

`terraform destroy` xóa 104 resource. Đã kiểm tra trực tiếp qua API:
- 2 instance EC2 ở trạng thái `terminated`, NAT Gateway `deleted`.
- EKS cluster và Lambda trả `ResourceNotFoundException`.
- Không còn VPC, Elastic IP hay GuardDuty detector.

## 3. Mười lỗi tìm ra hôm nay

| # | Lỗi | Mức độ |
|---|---|---|
| 10 | Apply từ state trống fail vì IP của Wazuh chưa biết lúc plan | Chặn deploy |
| 11 | `apply.sh` dừng trên manager mới cài (fingerprint + `set -e`) | Chặn deploy |
| 12 | **Script Active Response deadlock execd và agentd** — nguyên nhân gốc của việc mất alert và agent Disconnected | Nghiêm trọng nhất |
| 13 | Rule IMDS bắt nhầm `aws-node`: khoảng 1.400 false positive, Active Response kill nhầm CNI | Nghiêm trọng |
| 14 | SIGTERM bị PID 1 bỏ qua: script báo "stopped" nhưng container vẫn chạy | Vô hiệu hóa ngăn chặn |
| 15 | `wazuh-sync` báo fail sai khi chờ agent | Nhầm lẫn |
| 16 | Falco chỉ báo rule khớp đầu tiên, nên che rule "Kill Security Agent" | Mất phát hiện + ngăn chặn |
| 17 | **Lambda có thể vô hiệu hóa key của bất kỳ IAM user nào**, kể cả user vận hành | Nghiêm trọng |
| 18 | Wazuh không đọc được log GuardDuty | Mất cả một nguồn telemetry |
| 19 | Script tấn công/test chọn nhầm pod đã bị evict | Test cho kết quả rỗng |

Mỗi lỗi có test offline riêng nếu tái hiện được ngoài cluster:
- `tests/detection/ar_test.py` gọi script theo đúng cách execd gọi: giữ stdin mở, chỉ chấp nhận SIGKILL, có case `kube-system`. Script cũ bị treo trong test này.
- `tests/lambda/test_autofix.py` có 8 case. Code cũ fail 6.

Cả hai đã được đưa vào `scripts/scan.sh detection`, nên CI sẽ chạy chúng.

## 4. Kết quả theo kịch bản

| Bước | Detect | Prevent |
|---|---|---|
| 0. Image xấu | Cho qua (Audit) | ✅ Chặn image chưa ký, pod privileged, hostPath, cluster-admin |
| 1. Foothold | ✅ 100202 | — (exec của admin được phép theo thiết kế) |
| 2. Discovery | ✅ 100111, 100112 | ✅ Không có token, API trả 401 |
| D. IMDS | ✅ 100113 | ✅ Active Response kill container |
| 3. Escalation | ✅ 100300 (CloudTrail, 12,5 phút) | ✅ IAM AccessDenied |
| B. Escape | ✅ 100114 | ✅ PSS chặn `nsenter` + Active Response kill |
| G. Né tránh | ✅ 100115, 100116, 100117 | ✅ Active Response kill khi có lệnh kill agent |
| 4. Exfiltration mã hóa | ✅ 100119, 100120, 100130 | ✅ NetworkPolicy chặn egress + Active Response kill |
| I. Lạm dụng credential cloud | ✅ 100312 (GuardDuty) | ✅ Lambda cô lập role ngay lập tức |

## 5. Evidence

| Thư mục | Nội dung |
|---|---|
| `docs/evidence/20261127T050329Z-detect-rerun/` | Chế độ detect, kết quả delivery test (`08-delivery-test.txt`) |
| `docs/evidence/20261127T052536Z-prevent-rerun/` | Điều tra Active Response, log trên node, lỗi #10–#15 |
| `docs/evidence/20261127T071858Z-prevent-full/` | Smoke enforce, chuỗi tấn công enforce, Lambda, độ trễ từng rule, lỗi #16–#19 |

## 6. Trạng thái sau phiên

| Thành phần | Trạng thái |
|---|---|
| Lab stack | **Đã destroy sạch**, kiểm tra trực tiếp qua EC2/EKS/Lambda API |
| Bootstrap (S3 state, DynamoDB lock, ECR, OIDC roles) | Giữ nguyên theo thiết kế |
| Chi phí phiên | Khoảng 3 giờ lab — ước tính $1.5–2 |
| Git | Mọi bản sửa và evidence đã commit trên `main` (chưa push) |

Lưu ý: trong lúc test, script Active Response được vá trực tiếp lên node đang chạy, và Lambda cùng IAM policy được apply có target. Mọi thay đổi đều đã có trong code, nên lần deploy sau sẽ dùng bản đã sửa ngay từ đầu.

## 7. Kết luận và việc cần làm tiếp

**Đạt được:** vấn đề tồn đọng từ hôm qua đã có nguyên nhân gốc được chứng minh trên hạ tầng thật, đã được sửa và đo lại: không mất alert, kể cả khi restart manager. Toàn bộ chuỗi phát hiện → phản ứng (Falco → Wazuh → Active Response → kill container, và GuardDuty → EventBridge → Lambda → cô lập role) chạy được từ đầu đến cuối. Phần lớn các lỗi hôm nay (#10, #12, #13, #14, #16, #17, #18) **chỉ lộ ra khi chạy thật**: test offline trước đó đều pass. Hai lỗi #13 và #17 là loại tệ nhất cho một hệ thống phản ứng tự động: chúng làm hại chính hạ tầng nó cần bảo vệ.

**Còn lại:**
1. Push repo lên GitHub để CI ký image bằng Cosign. Hiện image chưa ký nên ở chế độ enforce không deploy được pod mới, chỉ giữ được pod cũ.
2. Chạy baseline 24 giờ để đo false positive. Ứng viên tinh chỉnh đầu tiên: rule 100205 báo mỗi lần Falco rollout.
3. Test RBAC chặn `exec` của developer (bước 1), và các kịch bản roadmap A, C, E, F.
4. Thêm một test offline chạy `apply.sh` trong container manager, để bắt các lỗi kiểu #11 trước khi deploy.
