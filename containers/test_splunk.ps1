# Ignore SSL certificate errors (for self-signed/internal certificates)
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

$headers = @{
    "Authorization" = "Splunk bb056fbe-a182-4ff6-8612-803df97d6d24"
    "Content-Type" = "application/json"
}
$body = @{
    event = "test message"
    sourcetype = "manual"
    index = "cyber_range"
} | ConvertTo-Json


$response = Invoke-RestMethod -Uri "https://172.16.25.2:8088/services/collector/event/1.0" -Method POST -Headers $headers -Body $body
$response