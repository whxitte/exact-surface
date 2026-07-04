{{- define "vantari.labels" -}}
app.kubernetes.io/name: vantari
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "vantari.env" -}}
- name: VANTARI_ENV
  value: {{ .Values.env | quote }}
envFrom:
  - secretRef:
      name: {{ .Values.existingSecret }}
{{- end -}}
