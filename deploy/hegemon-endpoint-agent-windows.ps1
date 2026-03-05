param(
  [string]$HegemonUrl,
  [string]$Token
)
python hegemon_endpoint_agent.py --hegemon-url $HegemonUrl --token $Token
