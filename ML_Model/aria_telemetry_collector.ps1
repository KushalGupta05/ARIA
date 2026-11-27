# aria_telemetry_collector.ps1
# ARIA Live Endpoint Telemetry Collector (FileShare Optimized)

$TelemetryDir = "C:\wazuh_telemetry"
$OutputFile = "$TelemetryDir\aria_metrics.json"

if (!(Test-Path -Path $TelemetryDir)) {
    New-Item -ItemType Directory -Path $TelemetryDir | Out-Null
}

$Counters = @(
    "\Network Interface(*)\TCP RSC Average Packet Size",
    "\Process(_Total)\Pool Paged Bytes",
    "\Process(_Total)\Handle Count",
    "\Memory\Free System Page Table Entries",
    "\Process(_Total)\Virtual Bytes",
    "\Memory\System Cache Resident Bytes",
    "\Process(_Total)\Virtual Bytes Peak",
    "\Process(_Total)\Thread Count",
    "\Process(_Total)\Working Set",
    "\Process(_Total)\Working Set Peak",
    "\Network Interface(*)\TCP Active RSC Connections",
    "\Process(_Total)\Page File Bytes",
    "\Process(_Total)\Working Set - Private",
    "\Memory\Standby Cache Normal Priority Bytes",
    "\Network Interface(*)\Bytes Sent/sec"
)

Write-Host "ARIA Telemetry Collector Started..." -ForegroundColor Green
Write-Host "Monitoring Top 15 Behavioral Features. Press Ctrl+C to stop." -ForegroundColor Yellow

while ($true) {
    try {
        $Sample = Get-Counter -Counter $Counters -SampleInterval 1 -MaxSamples 1 -ErrorAction SilentlyContinue

        if ($Sample) {
            function Get-Val($CounterName) {
                $reading = $Sample.CounterSamples | Where-Object Path -like "*$CounterName" | Select-Object -First 1
                if ($reading) { return [math]::Round($reading.CookedValue, 2) } else { return -1 }
            }

            # --- Capture Host Context (Top Processes & External Sockets) ---
            # Identify ARIA pipeline PIDs to filter out self-detection
            $ariaPids = @($PID)
            try {
                $wmiProcs = Get-CimInstance Win32_Process -Filter "Name LIKE '%python%' OR Name LIKE '%powershell%'" -ErrorAction SilentlyContinue
                foreach ($wp in $wmiProcs) {
                    if ($wp.CommandLine -match "aria_|frontend_api|uvicorn|telemetry_collector|RAG_Pipeline") {
                        $ariaPids += $wp.ProcessId
                    }
                }
            } catch {}

            $topProcesses = @()
            try {
                $procs = Get-Process -ErrorAction SilentlyContinue | Where-Object {
                    $_.Id -notin $ariaPids -and
                    (-not $_.Path -or ($_.Path -notlike "*\FYP\*" -and $_.Path -notlike "*\RAG_Pipeline\*"))
                } | Sort-Object WorkingSet64 -Descending | Select-Object -First 3
                foreach ($p in $procs) {
                    $pPath = ""
                    try { if ($p.Path) { $pPath = $p.Path } } catch {}
                    $topProcesses += [ordered]@{
                        "name" = $p.ProcessName
                        "pid" = $p.Id
                        "path" = $pPath
                        "working_set_mb" = [math]::Round($p.WorkingSet64 / 1MB, 2)
                    }
                }
            } catch {}

            $externalConns = @()
            try {
                $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
                    Where-Object {
                        $_.RemoteAddress -and
                        $_.RemoteAddress -notin @('127.0.0.1', '::1', '0.0.0.0') -and
                        $_.RemoteAddress -notlike "127.*" -and
                        $_.RemoteAddress -notlike "fe80:*" -and
                        $_.OwningProcess -notin $ariaPids
                    } | Select-Object -First 3
                foreach ($c in $conns) {
                    $cProc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
                    $cProcName = if ($cProc) { $cProc.ProcessName } else { "" }
                    $externalConns += [ordered]@{
                        "local_port" = $c.LocalPort
                        "remote_address" = $c.RemoteAddress
                        "remote_port" = $c.RemotePort
                        "pid" = $c.OwningProcess
                        "process_name" = $cProcName
                    }
                }
            } catch {}

            $Telemetry = [ordered]@{
                "Network_I_ActiveNIC_TCP_APS" = Get-Val "\tcp rsc average packet size"
                "Process_Pool_Paged Bytes" = Get-Val "\pool paged bytes"
                "Process_Handle Count" = Get-Val "\handle count"
                "Memory Free System Page Table Entries" = Get-Val "\free system page table entries"
                "Process_Virtual_Bytes" = Get-Val "\virtual bytes"
                "Memory System Cache Resident Bytes" = Get-Val "\system cache resident bytes"
                "Process_Virtual_Bytes Peak" = Get-Val "\virtual bytes peak"
                "Process_Thread Count" = Get-Val "\thread count"
                "Process_Working Set" = Get-Val "\working set"
                "Process_Working_Set_Peak" = Get-Val "\working set peak"
                "Network_I_ActiveNIC_ TCP Active RSC Connections" = Get-Val "\tcp active rsc connections"
                "Process_Page_File Bytes" = Get-Val "\page file bytes"
                "Process_Working_Set_ Private" = Get-Val "\working set - private"
                "Memory Standby Cache Normal Priority Bytes" = Get-Val "\standby cache normal priority bytes"
                "Network_I_ActiveNIC_ Bytes Sent sec" = Get-Val "\bytes sent/sec"
                "host_context" = [ordered]@{
                    "top_processes" = $topProcesses
                    "external_connections" = $externalConns
                }
            }

            $JsonPayload = $Telemetry | ConvertTo-Json -Depth 5 -Compress

            # --- ROBUST FILE WRITE METHOD ---
            # Explicitly allows Wazuh to read the file while PowerShell writes to it
            $fs = [System.IO.File]::Open($OutputFile, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
            $sw = New-Object System.IO.StreamWriter($fs)
            $sw.WriteLine($JsonPayload)
            $sw.Dispose()
            $fs.Dispose()

            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Pipeline Push -> $JsonPayload"
        }
    } catch {
        Write-Host "Error collecting telemetry: $_" -ForegroundColor Red
    }

    Start-Sleep -Seconds 2
}
