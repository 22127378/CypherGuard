# Báo cáo phiên làm việc — 26/11/2026

**Chủ đề:** Deploy CipherGuard v2.0 lên AWS thật lần đầu tiên và kiểm thử toàn bộ kịch bản tấn công
**Thời lượng:** ~4 giờ 20 phút (04:48–09:08 UTC)
**Kết quả:** Lab đã được tạo, kiểm thử, tìm & sửa 9 lỗi thật, thu thập evidence, và đã destroy sạch để dừng chi phí

---

## 1. Mục tiêu phiên

Trước phiên này, toàn bộ 7 phase của dự án (Phase 1–7 theo proposal) đã có code đầy đủ nhưng **chưa từng chạy trên AWS thật** — mọi kiểm chứng đều là offline (`terraform validate`, lint, test giả lập). Mục tiêu hôm nay:

1. Deploy toàn bộ hạ tầng lên tài khoản AWS thật (`ap-southeast-1`).
2. Chạy chuỗi tấn công mô phỏng ở cả hai chế độ: detect-only và prevent.
3. Lưu lại evidence làm bằng chứng cho từng success metric trong proposal.
4. Sửa mọi lỗi phát sinh khi chạy thật — vì code viết "đúng về lý thuyết" không đồng nghĩa "chạy đúng thật".

## 2. Diễn biến chính

### 2.1. Rào cản về danh tính AWS

Bắt đầu phiên, user đăng nhập bằng **root** của tài khoản AWS. Phát hiện ngay: **root không bao giờ gọi được `sts:AssumeRole`** (giới hạn cứng của AWS), nên không có cách nào hợp lệ để `kubectl` vào cluster EKS dù đã tạo riêng một IAM role `cluster-admin` để lách việc EKS không chấp nhận access-entry cho root. Giải pháp: user tạo một IAM user thật (`cipherguard-admin`) với quyền admin, dùng user này cho mọi thao tác còn lại.

### 2.2. Deploy hạ tầng (Terraform)

- `make bootstrap`: tạo S3 state, DynamoDB lock, ECR, OIDC provider + 3 IAM role cho GitHub Actions.
- `terraform apply` cho lab stack: VPC, EKS (cluster + node group 2× t3.large), Wazuh all-in-one, attacker host, GuardDuty, CloudTrail, Lambda auto-fix. Mất khoảng 15 phút cho EKS, tổng cộng ~20 phút.
- Gặp và sửa 2 lỗi Terraform ngay trong lúc apply (xem mục 3).

### 2.3. Deploy ứng dụng và policy lên cluster

- Build & push thủ công image `demo-app` lên ECR (vì repo chưa push GitHub nên pipeline CI/CD ký image chưa chạy được).
- `scripts/deploy.sh --mode detect`: cài Kyverno, Falco, cluster-policies (Audit), demo-app, đồng bộ rule Wazuh. Smoke test **pass 11/11**, bao gồm IRSA gọi SSM thành công thật.

### 2.4. Chạy chuỗi tấn công — lượt detect-only

`scripts/measure-latency.sh` chạy toàn bộ 8 bước (foothold, discovery, IMDS, escalation, container escape, defense evasion, exfiltration mã hóa). Lần chạy đầu: chỉ 2/9 rule Wazuh nhận được alert — phát hiện lỗi nghiêm trọng (mục 3.4). Sau khi sửa và rolling-update node group: **9/9 rule báo đúng trong 60s**, bao gồm toàn bộ chuỗi exfiltration AES-256-GCM+RSA và rule tương quan.

### 2.5. Chạy chuỗi tấn công — lượt prevent

`scripts/deploy.sh --mode enforce`: chuyển mọi policy sang Enforce, bật Active Response. Test trực tiếp 4 kịch bản admission — **cả 4/4 đều bị chặn đúng**:
- Image chưa ký bị Kyverno từ chối (success metric chính của proposal)
- Pod privileged bị từ chối
- hostPath `/` bị từ chối
- Gán cluster-admin cho ServiceAccount bị từ chối

### 2.6. Điều tra Active Response (~1.5 giờ)

Phát hiện và sửa 2 lỗi thật trong script cô lập container (mục 3.8, 3.9), nhưng phát hiện thêm một vấn đề độ tin cậy chưa giải quyết dứt điểm: pipeline Falco→Wazuh có tỷ lệ mất alert đáng kể khi test dồn dập, kể cả ở một lượt deploy hoàn toàn sạch (xem mục 4).

### 2.7. Destroy

`terraform destroy`: xóa sạch 104 resource (VPC, EKS, EC2, NAT Gateway, GuardDuty, CloudTrail, Lambda...). Xác nhận bằng EC2/EKS API trực tiếp (không qua AWS Tagging API vốn có độ trễ cache): cả 2 instance `terminated`, EKS cluster `ResourceNotFoundException`, VPC không còn. **Không còn resource nào tính phí theo giờ.**

## 3. Chín lỗi thật tìm ra và đã sửa

| # | Lỗi | Phát hiện lúc nào | Mức độ |
|---|---|---|---|
| 1 | `for_each` dùng ARN chưa biết lúc plan làm Terraform apply lỗi | Lần apply đầu tiên | Chặn deploy |
| 2 | Lambda `reserved_concurrent_executions` vượt quota tài khoản | Lần apply đầu tiên | Chặn deploy |
| 3 | `admin_cidr` validation chỉ nhận `/32`, không phù hợp môi trường IP xoay vòng | Lúc kết nối kubectl | Chặn truy cập |
| 4 | **`enable_bootstrap_user_data` chưa từng được set** — Wazuh agent và Active Response script bị âm thầm bỏ qua khỏi user-data của node **từ commit đầu tiên của dự án** | Khi thấy 0/9 rule Falco tới Wazuh | Nghiêm trọng nhất — vô hiệu hóa toàn bộ Phase 5 |
| 5 | Rule Wazuh 100301 báo động liên tục với hoạt động hợp lệ (nhầm cơ chế IAM Authenticator chuẩn của EKS với credential theft) | Khi soát log thật | False positive nghiêm trọng |
| 6 | Rule Falco phát hiện outbound bất thường không bao giờ fire vì phụ thuộc macro `outbound` mặc định có ngữ nghĩa khác kỳ vọng | Khi test exfiltration thật | Mất khả năng phát hiện bước 4 |
| 7 | Kyverno `reports-controller` thiếu RBAC đọc `clusterrolebindings`/`rolebindings` nên policy chặn đúng nhưng báo "not Ready" | Khi deploy policy prevent-mode | Cosmetic nhưng gây nhầm lẫn |
| 8 | Script Active Response nuốt lỗi parse JSON im lặng, luôn báo nhầm "host-level event" | Sau ~1 giờ debug | Che giấu lỗi thật, tốn thời gian điều tra |
| 9 | Script dùng `crictl` — không tồn tại trên AMI AL2023/containerd của EKS | Cùng lúc với lỗi #8 | Sẽ fail dù parse đúng |

Tất cả đã commit vào git với message mô tả rõ nguyên nhân, kèm test offline xác nhận fix đúng (không phá vỡ gì khác).

## 4. Vấn đề còn tồn đọng — chưa giải quyết dứt điểm

**Falco → Wazuh có tỷ lệ mất alert đáng kể** khi trigger lặp lại nhanh, kể cả sau một lượt deploy hoàn toàn sạch (không debug chồng chéo): khoảng 1/5 lần trigger mới có alert tới nơi. Đã loại trừ các nguyên nhân sau bằng kiểm chứng trực tiếp:

- **Không phải lỗi Falco** — pod log của Falco ghi nhận đủ 100% số lần trigger.
- **Không phải lỗi cấu hình `logcollector`** — xác nhận đang theo dõi đúng file.
- **Không phải lỗi script Active Response** — khi alert tới nơi, toàn bộ chuỗi dispatch → script → `ctr` hoạt động đúng, đo được độ trễ 3 giây.

Điểm mất mát nằm ở đâu đó giữa agent forward và việc rule match trên manager — chưa xác định được nguyên nhân gốc trong phạm vi chi phí/thời gian hợp lý của một phiên debug trên cluster đang tính tiền. Đã ghi chi tiết toàn bộ quá trình chẩn đoán vào [`docs/evidence/20261126T070646Z-prevent-run-verified/08-findings-summary.md`](evidence/20261126T070646Z-prevent-run-verified/08-findings-summary.md) để điều tra tiếp vào dịp khác.

**Cập nhật 27/11 (offline):** đã tìm ra và sửa ba lỗi cấu hình liên quan:
- Wazuh tách key có dấu chấm thành object lồng nhau (`container.id` → `container: {id}`), nên script Active Response không bao giờ đọc được container id. Đây là nguyên nhân của dòng log "no pod container id". Đã sửa, kèm test dùng alert thật sinh từ `wazuh-analysisd`.
- `apply.sh` chỉ restart manager khi cấu hình thật sự thay đổi, và sau khi restart thì cảnh báo nếu agent nào không Active.
- `logcollector` có `only-future-events=yes` mặc định, nên bỏ qua các dòng Falco ghi ra trong lúc agent reconnect. Đã chuyển sang `no`.

Cần một lượt chạy live tiếp theo để xác nhận tỷ lệ mất alert đã về 0.

**Cập nhật 27/11 (chạy lại live): đã giải quyết.** Nguyên nhân gốc thật sự là script Active Response bị deadlock: nó đọc stdin bằng `$(cat)` trong khi `wazuh-execd` giữ pipe mở. Script treo, kéo theo execd và `wazuh-agentd` treo theo, nên agent ngừng gửi keepalive và event. Sau khi sửa, delivery đạt 20/20, 30/30, và 20/20 kể cả khi restart manager giữa chừng. Active Response kill đúng container trong khoảng 1 giây. Chi tiết và 6 lỗi mới (#10–#15) ở [`docs/evidence/20261127T052536Z-prevent-rerun/08-findings-summary.md`](evidence/20261127T052536Z-prevent-rerun/08-findings-summary.md).

## 5. Evidence đã lưu

| Thư mục | Nội dung |
|---|---|
| `docs/evidence/20261126T065310Z-detect-only-verified/` | Cluster state, NetworkPolicy, PolicyReport, log Wazuh, kết quả đo độ trễ 2 lần (trước và sau khi sửa lỗi #4, #6) |
| `docs/evidence/20261126T070646Z-prevent-run-verified/` | Kết quả 4 test admission prevent-mode, log Active Response, báo cáo chẩn đoán đầy đủ vấn đề mục 4 |

## 6. Trạng thái hạ tầng sau phiên

| Thành phần | Trạng thái |
|---|---|
| Lab stack (VPC, EKS, EC2, NAT, GuardDuty, CloudTrail, Lambda) | **Đã destroy sạch**, xác nhận qua EC2/EKS API trực tiếp |
| Bootstrap (S3 state, DynamoDB lock, ECR, OIDC roles) | Giữ nguyên theo thiết kế — không tính phí theo giờ |
| Image demo-app | Còn trong ECR (`cipherguard/demo-app`), dùng lại được cho lần deploy sau |
| Chi phí phát sinh | ~4h20m chạy EKS + 2 node t3.large + Wazuh t3.large + NAT Gateway — ước tính dưới $2 |

## 7. Kết luận và việc cần làm tiếp

**Đạt được:** Toàn bộ 11 success metric cốt lõi của proposal đã có bằng chứng chạy thật, không chỉ lý thuyết — bao gồm cả thesis chính của dự án (phát hiện exfiltration bằng hành vi khi nội dung đã mã hóa, không đọc được). 9 lỗi thật đã được tìm ra chỉ nhờ việc deploy thật, điều mà kiểm tra offline không thể phát hiện.

**Còn lại:**
1. Điều tra nguyên nhân gốc của việc mất alert Falco→Wazuh (mục 4) — nên làm trong một phiên riêng, không chung với việc kiểm thử tổng thể, để dễ cô lập biến số.
2. Push repo lên GitHub để pipeline CI/CD (build, scan, ký Cosign) chạy thật — hiện image demo-app được build/push thủ công nên bỏ qua được bước ký, chưa test được đầy đủ nhánh "pipeline tự ký, Kyverno xác minh chữ ký thật từ CI".
3. Bài baseline 24 giờ để đo false positive (Phase 7, công cụ `make baseline` đã sẵn sàng).
4. Viết blog/quay video demo theo draft đã có ở `docs/blog-draft.md`.
