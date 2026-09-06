{{/* Canonical chart name (truncated at 63 chars). */}}
{{- define "csgw.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully qualified app name (release + chart, truncated). */}}
{{- define "csgw.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/* Common labels. */}}
{{- define "csgw.labels" -}}
app.kubernetes.io/name: {{ include "csgw.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/* Secret name holding the host key and encryption key. */}}
{{- define "csgw.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- include "csgw.fullname" . -}}
{{- end -}}
{{- end -}}

{{/* Image reference with tag fallback to appVersion. */}}
{{- define "csgw.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{/*
Encryption key material (base64) for the chart-managed Secret. Priority:
explicit values.secrets.encryptionKey, then the existing Secret's value
(stable across helm upgrades), then fresh generation. Generation uses
randBytes — 32 bytes of key material.
*/}}
{{- define "csgw.encryptionKeyB64" -}}
{{- if .Values.secrets.encryptionKey -}}
{{- .Values.secrets.encryptionKey -}}
{{- else -}}
{{- $existing := lookup "v1" "Secret" .Release.Namespace (include "csgw.fullname" .) -}}
{{- if $existing -}}
{{- index $existing.data "credential-key-v1" -}}
{{- else -}}
{{- randBytes 32 | b64enc -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* True when a host key comes from the Secret (values or existingSecret). */}}
{{- define "csgw.hostKeyProvided" -}}
{{- if or .Values.secrets.hostKey .Values.secrets.existingSecret -}}
true
{{- else -}}
false
{{- end -}}
{{- end -}}
