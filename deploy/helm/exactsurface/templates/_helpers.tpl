{{- define "exactsurface.labels" -}}
app.kubernetes.io/name: exactsurface
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "exactsurface.env" -}}
- name: EXACTSURFACE_ENV
  value: {{ .Values.env | quote }}
envFrom:
  - secretRef:
      name: {{ .Values.existingSecret }}
{{- end -}}
