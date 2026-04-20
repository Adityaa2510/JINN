$key = "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"

$headers = @{
    "Authorization" = "Bearer $key"
    "Content-Type" = "application/json"
    "HTTP-Referer" = "http://localhost:5000"
    "X-Title" = "SecOps"
}

$body = @{
    model = "deepseek/deepseek-chat-v3-0324:free"
    messages = @(
        @{role="user"; content="hello"}
    )
} | ConvertTo-Json -Depth 5

$response = Invoke-RestMethod `
    -Uri "https://openrouter.ai/api/v1/chat/completions" `
    -Method POST `
    -Headers $headers `
    -Body $body

Write-Output $response.choices[0].message.content