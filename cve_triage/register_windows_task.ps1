# CVE脅威度判定バッチを Windows タスクスケジューラに日次登録する。
# 使い方: powershell -ExecutionPolicy Bypass -File register_windows_task.ps1 [-Time 10:00]
# 解除:   Unregister-ScheduledTask -TaskName CveTriageDaily -Confirm:$false
param(
    [string]$Time = "10:00",
    [string]$TaskName = "CveTriageDaily"
)

$python = (Get-Command python -ErrorAction Stop).Source
$script = Join-Path $PSScriptRoot "cve_triage.py"

$action   = New-ScheduledTaskAction -Execute $python -Argument "`"$script`"" -WorkingDirectory $PSScriptRoot
$trigger  = New-ScheduledTaskTrigger -Daily -At $Time
# PCが停止していた場合は起動後に実行する
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
Write-Host "登録しました: $TaskName (毎日 $Time) / $python $script"
