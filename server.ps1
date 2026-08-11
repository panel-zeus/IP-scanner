# Zeus Scanner Core - Windows (PowerShell 5.1+)
# Serves index.html from the same folder and scans IPs over TLS/SNI.

$ErrorActionPreference = 'Stop'
$port = 8000
$url = "http://127.0.0.1:$port/"
$maxIpsPerRequest = 1000

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$uiPath = Join-Path $scriptDir 'index.html'
$cssPath = Join-Path $scriptDir 'tailwind.css'
if (Test-Path $uiPath) {
    $htmlContent = Get-Content -Path $uiPath -Raw -Encoding UTF8
} else {
    $htmlContent = "<h1>index.html not found next to server.ps1</h1>"
}
$cssContent = if (Test-Path $cssPath) { Get-Content -Path $cssPath -Raw -Encoding UTF8 } else { '' }

# Tls13 is absent on .NET Framework / PowerShell 5.1, so enable it only if defined.
try {
    $protocols = [System.Net.SecurityProtocolType]::Tls12
    if ([enum]::GetNames([System.Net.SecurityProtocolType]) -contains 'Tls13') {
        $protocols = $protocols -bor [System.Net.SecurityProtocolType]::Tls13
    }
    [System.Net.ServicePointManager]::SecurityProtocol = $protocols
} catch {
    Write-Host "Warning: could not set TLS protocols: $($_.Exception.Message)" -ForegroundColor Yellow
}

function Test-ZeusHost {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Length -gt 253) { return $false }
    return $Value -match '^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$'
}

function Write-ZeusResponse {
    param($Response, [int]$StatusCode, [string]$Body, [string]$ContentType = 'application/json')
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
        $Response.StatusCode = $StatusCode
        $Response.ContentType = $ContentType
        $Response.ContentLength64 = $bytes.Length
        $Response.OutputStream.Write($bytes, 0, $bytes.Length)
    } catch {
    } finally {
        try { $Response.Close() } catch {}
    }
}

function Invoke-ZeusScan {
    param([string[]]$Ips, [string]$Sni, [int[]]$Ports = @(443), [int]$Passes = 3,
          [System.Threading.ManualResetEventSlim]$CancelEvent)

    $timeoutMs = 3500
    # 403/409/429 means the edge answered but refused us, so it is not a clean IP.
    $blockedStatuses = @(403, 409, 429)

    $state = @{}
    foreach ($ip in $Ips) {
        $state[$ip] = [PSCustomObject]@{
            Pings = [System.Collections.ArrayList]::new()
            Tcps = [System.Collections.ArrayList]::new()
            Port = 0
            Cloudflare = $false
            Status = 0
            Blocked = $false
        }
    }

    # Pass 0 probes every selected port to pick one; later passes reuse the winner.
    for ($pass = 0; $pass -lt $Passes; $pass++) {
        if ($CancelEvent.IsSet) { break }
        $targets = @()
        foreach ($ip in $Ips) {
            if ($pass -eq 0) {
                foreach ($port in $Ports) { $targets += @{ IP = $ip; Port = $port } }
            } elseif ($state[$ip].Port -ne 0) {
                $targets += @{ IP = $ip; Port = $state[$ip].Port }
            }
        }
        if ($targets.Count -eq 0) { continue }

        $tasks = @()
        foreach ($target in $targets) {
            try {
                $tcp = New-Object System.Net.Sockets.TcpClient
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $asyncResult = $tcp.BeginConnect($target.IP, $target.Port, $null, $null)
                $tasks += [PSCustomObject]@{
                    IP = $target.IP; Port = $target.Port
                    Tcp = $tcp; AsyncResult = $asyncResult; Stopwatch = $sw
                    TcpMs = 0; State = 0; Success = $false; Ping = 0; Status = 0; Cloudflare = $false
                    SslStream = $null; SslAsyncResult = $null; ReadAsyncResult = $null
                    Buffer = New-Object byte[] 8192
                }
            } catch {}
        }

        $overallSw = [System.Diagnostics.Stopwatch]::StartNew()
        while ($overallSw.ElapsedMilliseconds -lt $timeoutMs -and -not $CancelEvent.IsSet) {
            $allDone = $true
            foreach ($task in $tasks) {
                if ($task.State -eq 0) {
                    $allDone = $false
                    if ($task.AsyncResult.IsCompleted) {
                        try {
                            $task.Tcp.EndConnect($task.AsyncResult)
                            $task.TcpMs = $task.Stopwatch.ElapsedMilliseconds
                            $stream = $task.Tcp.GetStream()
                            $task.SslStream = New-Object System.Net.Security.SslStream($stream, $false, { $true })
                            $task.SslAsyncResult = $task.SslStream.BeginAuthenticateAsClient($Sni, $null, $null)
                            $task.State = 1
                        } catch { $task.State = 3 }
                    }
                }
                elseif ($task.State -eq 1) {
                    $allDone = $false
                    if ($task.SslAsyncResult.IsCompleted) {
                        try {
                            $task.SslStream.EndAuthenticateAsClient($task.SslAsyncResult)
                            $reqStr = "GET / HTTP/1.1`r`nHost: $Sni`r`nUser-Agent: Mozilla/5.0 (Zeus-Scanner)`r`nAccept: */*`r`nConnection: close`r`n`r`n"
                            $reqBytes = [System.Text.Encoding]::ASCII.GetBytes($reqStr)
                            $task.SslStream.Write($reqBytes, 0, $reqBytes.Length)
                            $task.ReadAsyncResult = $task.SslStream.BeginRead($task.Buffer, 0, $task.Buffer.Length, $null, $null)
                            $task.State = 2
                        } catch { $task.State = 3 }
                    }
                }
                elseif ($task.State -eq 2) {
                    $allDone = $false
                    if ($task.ReadAsyncResult.IsCompleted) {
                        $task.Stopwatch.Stop()
                        try {
                            $bytesRead = $task.SslStream.EndRead($task.ReadAsyncResult)
                            if ($bytesRead -gt 0) {
                                $resp = [System.Text.Encoding]::ASCII.GetString($task.Buffer, 0, $bytesRead)
                                if ($resp -match "^HTTP/1\.[01] (\d{3})") {
                                    $task.Status = [int]$Matches[1]
                                    $task.Cloudflare = $resp -match '(?im)^(cf-ray:|server:\s*cloudflare)'
                                    if (($blockedStatuses -notcontains $task.Status) -and $task.Cloudflare) {
                                        $task.Success = $true
                                        $task.Ping = $task.Stopwatch.ElapsedMilliseconds
                                    }
                                }
                            }
                        } catch {}
                        $task.State = 3
                    }
                }
            }
            if ($allDone) { break }
            Start-Sleep -Milliseconds 10
        }

        foreach ($task in $tasks) {
            $entry = $state[$task.IP]
            if ($task.Status -ne 0) { $entry.Status = $task.Status }
            if ($task.Success) {
                # First pass may probe several ports; keep the first one that worked.
                if ($entry.Port -eq 0) { $entry.Port = $task.Port }
                if ($entry.Port -eq $task.Port) {
                    [void]$entry.Pings.Add([int]$task.Ping)
                    [void]$entry.Tcps.Add([int]$task.TcpMs)
                    if ($task.Cloudflare) { $entry.Cloudflare = $true }
                }
            } elseif ($blockedStatuses -contains $task.Status) {
                $entry.Blocked = $true
            }
            if ($null -ne $task.SslStream) { try { $task.SslStream.Dispose() } catch {} }
            if ($null -ne $task.Tcp) { try { $task.Tcp.Close() } catch {} }
        }

        # A back-to-back reconnect reuses a warm path and hides real loss.
        if ($pass -lt ($Passes - 1)) { Start-Sleep -Milliseconds 120 }
    }

    $results = @()
    foreach ($ip in $Ips) {
        $entry = $state[$ip]
        if ($entry.Pings.Count -gt 0) {
            $sorted = @($entry.Pings | Sort-Object)
            $okCount = $sorted.Count
            $min = $sorted[0]
            $max = $sorted[$okCount - 1]
            $avg = ($sorted | Measure-Object -Average).Average
            if (($okCount % 2) -eq 0) {
                $mid = $okCount / 2
                $median = [int][math]::Round(($sorted[$mid - 1] + $sorted[$mid]) / 2.0)
            } else {
                $median = [int]$sorted[[math]::Floor($okCount / 2)]
            }

            $stdev = 0
            if ($okCount -ge 2) {
                $sumSq = 0.0
                foreach ($v in $sorted) { $sumSq += [math]::Pow($v - $avg, 2) }
                $stdev = [int][math]::Sqrt($sumSq / ($okCount - 1))
            }

            $loss = [int][math]::Round((($Passes - $okCount) / [double]$Passes) * 100)
            if ($loss -lt 0) { $loss = 0 }
            $usable = ($okCount * 2) -gt $Passes

            # Same weighting as the Python core so both agree on ranking.
            $score = 100.0
            $score -= $loss * 0.9
            $score -= [math]::Min(45.0, $median / 1000.0 * 45.0)
            $score -= [math]::Min(20.0, $stdev / 200.0 * 20.0)
            $score = [int][math]::Max(0, [math]::Min(100, [math]::Round($score)))
            if (-not $usable) { $score = 0 }

            $results += @{
                ip = $ip; success = $usable; port = $entry.Port
                ping = [int]$min; median = $median; avg = [int][math]::Floor($avg)
                worst = [int]$max; jitter = [int]($max - $min); stdev = $stdev
                loss = $loss; score = $score
                tcp = [int]($entry.Tcps | Measure-Object -Minimum).Minimum; tls = 0
                ok = $okCount; attempts = $Passes
                status = $entry.Status; cloudflare = $entry.Cloudflare; speed = $null
            }
        } else {
            $err = if ($entry.Blocked) { "blocked (HTTP $($entry.Status))" } else { "failed" }
            $results += @{ ip = $ip; success = $false; error = $err }
        }
    }
    return , $results
}

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add($url)
$activeScans = [System.Collections.Concurrent.ConcurrentDictionary[string,System.Threading.ManualResetEventSlim]]::new()
$cancelledScans = [System.Collections.Concurrent.ConcurrentDictionary[string,bool]]::new()
$workers = [System.Collections.ArrayList]::new()

try {
    $listener.Start()
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "  Zeus Scanner Core (Unified) is RUNNING!" -ForegroundColor Green
    Write-Host "  Listening on: $url" -ForegroundColor Yellow
    Write-Host "  Do NOT close this window during scan." -ForegroundColor Gray
    Write-Host "==========================================" -ForegroundColor Cyan
    Start-Process $url
} catch {
    Write-Host "Error starting server: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

try {
    while ($listener.IsListening) {
        foreach ($job in @($workers)) {
            if ($job.Async.IsCompleted) {
                try { [void]$job.Shell.EndInvoke($job.Async) } catch {}
                $job.Shell.Dispose()
                [void]$workers.Remove($job)
            }
        }
        # One request at a time would starve /api/ping during a long scan, so each
        # context is handed to a runspace and the accept loop stays free.
        $context = $listener.GetContext()
        $worker = [powershell]::Create()
        [void]$worker.AddScript({
            param($context, $htmlContent, $cssContent, $maxIps, $activeScans, $cancelledScans, $scanFn, $hostFn, $writeFn)

            ${function:Invoke-ZeusScan} = [scriptblock]::Create($scanFn)
            ${function:Test-ZeusHost} = [scriptblock]::Create($hostFn)
            ${function:Write-ZeusResponse} = [scriptblock]::Create($writeFn)

            $request = $context.Request
            $response = $context.Response
            try {
                $response.AppendHeader("Access-Control-Allow-Origin", "*")
                $response.AppendHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
                $response.AppendHeader("Access-Control-Allow-Headers", "Content-Type")
                $path = $request.Url.AbsolutePath

                if ($request.HttpMethod -eq "OPTIONS") {
                    $response.StatusCode = 204
                    $response.Close()
                }
                elseif ($path -eq "/" -and $request.HttpMethod -eq "GET") {
                    Write-ZeusResponse $response 200 $htmlContent "text/html; charset=utf-8"
                }
                elseif ($path -eq "/tailwind.css" -and $request.HttpMethod -eq "GET") {
                    Write-ZeusResponse $response 200 $cssContent "text/css; charset=utf-8"
                }
                elseif ($path -eq "/api/ping" -and $request.HttpMethod -eq "GET") {
                    Write-ZeusResponse $response 200 '{"status":"online","xray":false,"capabilities":{"xray":false,"speed":false,"precise":false}}'
                }
                elseif ($path -eq "/api/cancel" -and $request.HttpMethod -eq "POST") {
                    $reader = New-Object System.IO.StreamReader($request.InputStream, [System.Text.Encoding]::UTF8)
                    try { $json = $reader.ReadToEnd() | ConvertFrom-Json } catch { $json = $null } finally { $reader.Dispose() }
                    $scanId = if ($null -ne $json) { [string]$json.scan_id } else { '' }
                    if ($scanId -notmatch '^[A-Za-z0-9_-]{8,80}$') {
                        Write-ZeusResponse $response 400 '{"error":"invalid scan id"}'
                        return
                    }
                    $cancelEvent = $null
                    $cancelled = $activeScans.TryGetValue($scanId, [ref]$cancelEvent)
                    if ($cancelled) { $cancelEvent.Set() } else {
                        if ($cancelledScans.Count -gt 1000) { $cancelledScans.Clear() }
                        $cancelledScans[$scanId] = $true
                    }
                    Write-ZeusResponse $response 200 '{"cancelled":true}'
                }
                elseif ($path -eq "/api/scan" -and $request.HttpMethod -eq "POST") {
                    $reader = New-Object System.IO.StreamReader($request.InputStream, [System.Text.Encoding]::UTF8)
                    $body = $reader.ReadToEnd()
                    $reader.Dispose()
                    try { $json = $body | ConvertFrom-Json }
                    catch {
                        Write-ZeusResponse $response 400 '{"error":"malformed json"}'
                        return
                    }

                    $ips = @()
                    if ($null -ne $json.ips) { $ips = @($json.ips) }
                    elseif ($null -ne $json.ip) { $ips = @($json.ip) }
                    $sni = [string]$json.sni

                    if (-not (Test-ZeusHost $sni)) {
                        Write-ZeusResponse $response 400 '{"error":"invalid sni"}'
                    }
                    else {
                        $allowedPorts = @(443, 2053, 2083, 2087, 2096, 8443)
                        $ports = @()
                        if ($null -ne $json.ports) {
                            $ports = @($json.ports | Where-Object { $allowedPorts -contains [int]$_ } | ForEach-Object { [int]$_ })
                        }
                        if ($ports.Count -eq 0) { $ports = @(443) }

                        $passes = 3
                        if ($null -ne $json.passes -and [int]$json.passes -ge 1 -and [int]$json.passes -le 10) {
                            $passes = [int]$json.passes
                        }

                        $ips = @($ips | Where-Object {
                            $parsedIp = $null
                            [System.Net.IPAddress]::TryParse(([string]$_).Trim(), [ref]$parsedIp)
                        } | ForEach-Object { ([string]$_).Trim() } | Select-Object -Unique)
                        if ($ips.Count -gt $maxIps) {
                            Write-ZeusResponse $response 400 '{"error":"too many ips"}'
                            return
                        }
                        if ($ips.Count -eq 0) {
                            Write-ZeusResponse $response 400 '{"error":"no valid ips"}'
                            return
                        }
                        $scanId = [string]$json.scan_id
                        if ($scanId -notmatch '^[A-Za-z0-9_-]{8,80}$') {
                            Write-ZeusResponse $response 400 '{"error":"invalid scan id"}'
                            return
                        }
                        $cancelEvent = [System.Threading.ManualResetEventSlim]::new($false)
                        $activeScans[$scanId] = $cancelEvent
                        $wasCancelled = $false
                        if ($cancelledScans.TryRemove($scanId, [ref]$wasCancelled)) { $cancelEvent.Set() }
                        try {
                            $results = Invoke-ZeusScan -Ips $ips -Sni $sni -Ports $ports -Passes $passes -CancelEvent $cancelEvent
                            $resJson = ConvertTo-Json -InputObject @{ results = @($results) } -Compress -Depth 4
                            Write-ZeusResponse $response 200 $resJson
                        } finally {
                            $removedEvent = $null
                            [void]$activeScans.TryRemove($scanId, [ref]$removedEvent)
                            $cancelEvent.Dispose()
                        }
                    }
                }
                else {
                    Write-ZeusResponse $response 404 '{"error":"not found"}'
                }
            } catch {
                try { Write-ZeusResponse $response 500 '{"error":"internal error"}' } catch {}
            }
        })
        [void]$worker.AddArgument($context)
        [void]$worker.AddArgument($htmlContent)
        [void]$worker.AddArgument($cssContent)
        [void]$worker.AddArgument($maxIpsPerRequest)
        [void]$worker.AddArgument($activeScans)
        [void]$worker.AddArgument($cancelledScans)
        [void]$worker.AddArgument(${function:Invoke-ZeusScan}.ToString())
        [void]$worker.AddArgument(${function:Test-ZeusHost}.ToString())
        [void]$worker.AddArgument(${function:Write-ZeusResponse}.ToString())
        $async = $worker.BeginInvoke()
        [void]$workers.Add([PSCustomObject]@{ Shell = $worker; Async = $async })
    }
}
catch {
    Write-Host "Server loop stopped: $($_.Exception.Message)" -ForegroundColor Red
}
finally {
    foreach ($job in @($workers)) {
        try { $job.Shell.Stop() } catch {}
        $job.Shell.Dispose()
    }
    try { $listener.Stop() } catch {}
    try { $listener.Close() } catch {}
}
