{{- define "demo-app.labels" -}}
app.kubernetes.io/name: demo-app
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: cipherguard
{{- end -}}

{{- define "demo-app.selector" -}}
app.kubernetes.io/name: demo-app
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "demo-app.image" -}}
{{- $repo := required "image.repository is required" .Values.image.repository -}}
{{- $digest := required "image.digest is required (sha256:...)" .Values.image.digest -}}
{{- if not (hasPrefix "sha256:" $digest) -}}
{{- fail "image.digest must start with sha256:" -}}
{{- end -}}
{{ $repo }}@{{ $digest }}
{{- end -}}
