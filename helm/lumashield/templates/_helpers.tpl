{{/*
Expand the name of the chart.
*/}}
{{- define "lumashield.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "lumashield.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "lumashield.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "lumashield.labels" -}}
helm.sh/chart: {{ include "lumashield.chart" . }}
{{ include "lumashield.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "lumashield.selectorLabels" -}}
app.kubernetes.io/name: {{ include "lumashield.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "lumashield.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "lumashield.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Control Plane name
*/}}
{{- define "lumashield.controlPlane.name" -}}
{{- printf "%s-control-plane" (include "lumashield.fullname" .) }}
{{- end }}

{{/*
Agent name
*/}}
{{- define "lumashield.agent.name" -}}
{{- printf "%s-agent" (include "lumashield.fullname" .) }}
{{- end }}

{{/*
Redis address
*/}}
{{- define "lumashield.redis.addr" -}}
{{- if .Values.redis.enabled }}
{{- printf "%s-redis-master:6379" .Release.Name }}
{{- else }}
{{- .Values.externalRedis.addr }}
{{- end }}
{{- end }}
