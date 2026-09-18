$ErrorActionPreference = "Stop"
$policy = Join-Path (Split-Path $PSScriptRoot -Parent) "docs\CAPTURE_CAMPAIGN_POLICY_V1.md"
throw "Disabled legacy launcher: it couples one-shot A/B process lifetimes to the 24 h campaign. Implement and qualify the continuous generational collector and 15-minute chained raw segments defined in $policy before another endurance run."
