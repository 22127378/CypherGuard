{{- define "cp.mode" -}}
{{- $m := .Values.mode -}}
{{- if not (has $m (list "Enforce" "Audit")) -}}
{{- fail "mode must be Enforce or Audit" -}}
{{- end -}}
{{ $m }}
{{- end -}}

{{/* Enforce -> Deny the request; Audit -> admit and record in PolicyReports. */}}
{{- define "cp.actions" -}}
{{- if eq (include "cp.mode" .) "Enforce" -}}
[Deny]
{{- else -}}
[Audit]
{{- end -}}
{{- end -}}

{{- define "cp.labels" -}}
app.kubernetes.io/part-of: cipherguard
app.kubernetes.io/managed-by: {{ .Release.Service }}
cipherguard.io/policy-mode: {{ include "cp.mode" . }}
{{- end -}}

{{- define "cp.repository" -}}
{{- required "images.repository is required" .Values.images.repository -}}
{{- end -}}

{{/* CEL list literal, e.g. ['demo', 'other'] */}}
{{- define "cp.celList" -}}
[{{- range $i, $v := . -}}{{- if $i -}}, {{ end -}}'{{ $v }}'{{- end -}}]
{{- end -}}

{{/* Every container in the pod spec, including init and ephemeral. */}}
{{- define "cp.containersVar" -}}
- name: containers
  expression: >-
    object.spec.containers
    + object.spec.?initContainers.orValue([])
    + object.spec.?ephemeralContainers.orValue([])
{{- end -}}

{{- define "cp.podRules" -}}
resourceRules:
  - apiGroups: [""]
    apiVersions: ["v1"]
    operations: ["CREATE", "UPDATE"]
    resources: ["pods"]
{{- end -}}
