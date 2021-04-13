{{- if .Alerts -}}
{{- range $severity, $alerts := (groupAlertsByLabel .Alerts "severity") -}}
Status: {{ $severity }}
{{- range $index, $alert := $alerts }}
- Alert: {{ $alert.Labels.alertname }}
  Summary: {{ $alert.Annotations.summary }}
  Description: {{ $alert.Annotations.description }}
{{ end }}
{{ end }}
{{ else -}}
Status: OK
{{- end -}}
