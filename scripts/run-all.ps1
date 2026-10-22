Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
$PathToAtomicsFolder = "C:\AtomicRedTeam\atomics"

$tests = @(
  "T1082:1","T1083:1","T1057:2","T1016:1","T1018:1","T1033:1","T1087.001:8",
  "T1059.001:1","T1059.003:1","T1053.005:1","T1547.001:1","T1136.001:4",
  "T1543.003:1","T1105:7","T1218.011:1","T1218.005:1"
)

$out = "C:\AtomicRedTeam\results-final.csv"
"technique,test,start_utc,end_utc,status,sysmon_events" | Out-File $out -Encoding ascii
$fmt = 'yyyy-MM-dd HH:mm:ss'

foreach ($item in $tests) {
  $id, $num = $item.Split(':')
  Write-Host "=== $id (test $num) ===" -ForegroundColor Cyan
  $start = Get-Date
  $status = "ok"
  try {
    Invoke-AtomicTest $id -TestNumbers $num -GetPrereqs -ErrorAction Stop | Out-Null
    $start = Get-Date
    Invoke-AtomicTest $id -TestNumbers $num -TimeoutSeconds 120 -ErrorAction Stop | Out-Null
  } catch { $status = "error"; Write-Host $_.Exception.Message -ForegroundColor Yellow }
  $end = Get-Date
  Start-Sleep 20

  $n = (Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=$start; EndTime=$end} -ErrorAction SilentlyContinue | Measure-Object).Count
  Invoke-AtomicTest $id -TestNumbers $num -Cleanup -ErrorAction SilentlyContinue | Out-Null

  "$id,$num,$($start.ToUniversalTime().ToString($fmt)),$($end.ToUniversalTime().ToString($fmt)),$status,$n" | Add-Content $out
  Start-Sleep 20
}
Write-Host "Done. Results in $out" -ForegroundColor Green
