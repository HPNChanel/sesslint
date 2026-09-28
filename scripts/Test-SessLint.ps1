# T-12: offline Windows PowerShell 5.1+ acceptance. No Python or admin required.
[CmdletBinding()]
param(
    [string]$PackageRoot = $PSScriptRoot,
    [Parameter(Mandatory = $true)][string]$ReceiptPath
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$utf8 = New-Object System.Text.UTF8Encoding($false)
$PackageRoot = [IO.Path]::GetFullPath($PackageRoot)
$ReceiptPath = [IO.Path]::GetFullPath($ReceiptPath)
if (Test-Path -LiteralPath $ReceiptPath) { throw 'Receipt already exists; choose a new path.' }
$logs = $ReceiptPath + '.logs'
if (Test-Path -LiteralPath $logs) { throw 'Log directory already exists.' }
[IO.Directory]::CreateDirectory($logs) | Out-Null
$receipt = [ordered]@{ schema_version = 1; status = 'FAIL'; driver = 'powershell';
    driver_version = $PSVersionTable.PSVersion.ToString(); platform = 'Windows';
    os_build = [Environment]::OSVersion.Version.ToString();
    architecture = $env:PROCESSOR_ARCHITECTURE; kind = 'binary'; checks = @();
    clean_windows = 'UNVERIFIED'; source_immutable = $false }

function Read-Json([string]$Path) {
    return [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8) | ConvertFrom-Json
}
function Hash([string]$Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Inside([string]$Root, [string]$Relative) {
    $full = [IO.Path]::GetFullPath((Join-Path $Root $Relative))
    if (-not $full.StartsWith($Root.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Path escapes package/work directory.'
    }
    return $full
}
function Optional($Object, [string]$Name, $Default) {
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return ,$Default }
    return ,$property.Value
}
function Field($Object, [string]$Name) {
    foreach ($part in $Name.Split('.')) {
        $property = $Object.PSObject.Properties[$part]
        if ($null -eq $property) { throw "Missing result field: $Name" }
        $Object = $property.Value
    }
    return ,$Object
}
function Json($Value) { return ConvertTo-Json -InputObject $Value -Depth 100 -Compress }
function Require([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Quote-Argument([string]$Value) {
    # Windows CommandLineToArgvW quoting, including quotes and trailing backslashes.
    return '"' + [regex]::Replace([regex]::Replace($Value, '(\\*)"', '$1$1\"'), '(\\+)$', '$1$1') + '"'
}

try {
    $manifest = Read-Json (Join-Path $PackageRoot 'windows-acceptance.json')
    Require ($manifest.schema_version -eq 1) 'Unsupported package manifest.'
    Require ($manifest.version -match '^\d+\.\d+\.\d+$') 'Invalid package version.'
    foreach ($required in @($manifest.binary, $manifest.starter_kit, 'Test-SessLint.ps1', 'START_HERE.md', 'kit/VERSION', 'kit/smoke-contract.json', 'kit/LICENSE', 'kit/NOTICE', 'kit/QUICKSTART.md', 'kit/VERIFYING.md')) {
        Require ($null -ne $manifest.files.PSObject.Properties[$required]) ('Missing checksum entry: ' + $required)
    }
    foreach ($entry in $manifest.files.PSObject.Properties) {
        $file = Inside $PackageRoot $entry.Name
        Require ((Hash $file) -ceq $entry.Value) ('Checksum mismatch: ' + $entry.Name)
    }
    $binary = Inside $PackageRoot $manifest.binary
    Require ([IO.Path]::GetFileName($binary) -ceq $manifest.binary) 'Binary name must be flat.'
    Require ($manifest.binary.StartsWith('sesslint-' + $manifest.version + '-windows-')) 'Wrong binary identity.'
    Require (([IO.File]::ReadAllText((Inside $PackageRoot 'kit/VERSION'), [Text.Encoding]::UTF8)).Trim() -ceq $manifest.version) 'Starter-kit version mismatch.'
    $receipt.version = $manifest.version
    $receipt.artifact = $manifest.binary
    $receipt.artifact_sha256 = Hash $binary
    $receipt.starter_kit_sha256 = Hash (Inside $PackageRoot $manifest.starter_kit)
    $receipt.commit = $manifest.commit
    $receipt.package_manifest_sha256 = Hash (Join-Path $PackageRoot 'windows-acceptance.json')
    $receipt.python_commands_on_host = @(Get-Command python.exe, python3.exe, py.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source)
    $receipt.python_registry_present = (Test-Path 'HKCU:\Software\Python') -or (Test-Path 'HKLM:\Software\Python')
    $work = Join-Path ([IO.Path]::GetTempPath()) ('sesslint handoff ' + [char]0x0111 + ' ' + [Guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($work) | Out-Null
    $receipt.work_directory = $work
    # Copy only manifest-verified kit members; no archive extraction or real agent discovery.
    foreach ($entry in $manifest.files.PSObject.Properties) {
        if ($entry.Name.StartsWith('kit/')) {
            $target = Inside $work $entry.Name.Substring(4)
            [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target)) | Out-Null
            [IO.File]::Copy((Inside $PackageRoot $entry.Name), $target, $false)
        }
    }
    $relocated = Join-Path $work $manifest.binary
    [IO.File]::Copy($binary, $relocated, $false)
    $contract = Read-Json (Join-Path $work 'smoke-contract.json')
    Require ($contract.schema_version -eq 1 -and $contract.cases.Count -eq 32) 'Invalid smoke contract.'
    Require (@($contract.cases.id | Select-Object -Unique).Count -eq 32) 'Duplicate case IDs.'
    $receipt.contract_sha256 = Hash (Join-Path $work 'smoke-contract.json')
    foreach ($copy in $contract.copies) {
        $target = Inside $work $copy[1]
        [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target)) | Out-Null
        [IO.File]::Copy((Inside $work $copy[0]), $target, $false)
    }
    $before = @{}
    Get-ChildItem -LiteralPath (Join-Path $work 'examples') -File | ForEach-Object { $before[$_.Name] = Hash $_.FullName }
    $isolated = @{}
    foreach ($key in @('HOME','USERPROFILE','CODEX_HOME','CLAUDE_CONFIG_DIR','APPDATA','LOCALAPPDATA','TEMP','TMP','XDG_CACHE_HOME')) {
        $path = Join-Path $work ('isolated/' + $key)
        [IO.Directory]::CreateDirectory($path) | Out-Null
        $isolated[$key] = $path
    }
    $outputs = @{}
    foreach ($original in $contract.cases) {
        $case = (Json $original).Replace('{work}', $work.Replace('\','/')).Replace('{version}', $manifest.version) | ConvertFrom-Json
        Require ($case.id -match '^[a-z0-9-]+$') 'Invalid case ID.'
        $info = New-Object Diagnostics.ProcessStartInfo
        $info.FileName = $relocated
        $info.Arguments = (@($case.args | ForEach-Object { Quote-Argument $_ }) -join ' ')
        $info.WorkingDirectory = $work
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        $info.RedirectStandardInput = $true
        $info.StandardOutputEncoding = $utf8
        $info.StandardErrorEncoding = $utf8
        foreach ($key in @($info.EnvironmentVariables.Keys)) {
            if ($key -match '^(PYTHON|COVERAGE)') { $info.EnvironmentVariables.Remove($key) }
        }
        foreach ($key in $isolated.Keys) { $info.EnvironmentVariables[$key] = $isolated[$key] }
        $info.EnvironmentVariables['PATH'] = Join-Path $env:SystemRoot 'System32'
        $info.EnvironmentVariables['NO_COLOR'] = '1'
        $process = New-Object Diagnostics.Process
        $process.StartInfo = $info
        [void]$process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        foreach ($message in (Optional $case 'stdin_jsonl' @())) {
            # ASCII JSON is also valid UTF-8; avoids legacy console stdin codepages.
            $line = [regex]::Replace((Json $message), '[^\x00-\x7F]', { param($m) '\u{0:x4}' -f [int][char]$m.Value })
            $process.StandardInput.WriteLine($line)
        }
        $process.StandardInput.Close()
        if (-not $process.WaitForExit(120000)) {
            # This PID was started by this runner; terminate its own descendants too.
            & (Join-Path $env:SystemRoot 'System32/taskkill.exe') /PID $process.Id /T /F | Out-Null
            throw ('Timeout: ' + $case.id)
        }
        $output = $stdout.GetAwaiter().GetResult()
        $errorOutput = $stderr.GetAwaiter().GetResult()
        [IO.File]::WriteAllText((Join-Path $logs ($case.id + '.stdout.log')), $output, $utf8)
        [IO.File]::WriteAllText((Join-Path $logs ($case.id + '.stderr.log')), $errorOutput, $utf8)
        $exitCode = $process.ExitCode
        $process.Dispose()
        Require ($case.exit_codes -contains $exitCode) ('Unexpected exit: ' + $case.id + ': ' + $exitCode)
        foreach ($literal in (Optional $case 'contains' @())) { Require ($output.Contains($literal)) ('Missing code: ' + $case.id) }
        $same = Optional $case 'stdout_equals' $null
        if ($null -ne $same) { Require ($output -ceq $outputs[$same]) 'Parallel/serial output differs.' }
        $equals = Optional $case 'json_equals' ([pscustomobject]@{})
        $sets = Optional $case 'json_sets' ([pscustomobject]@{})
        if (@($equals.PSObject.Properties).Count -or @($sets.PSObject.Properties).Count) {
            $parsed = $output | ConvertFrom-Json
            foreach ($entry in $equals.PSObject.Properties) {
                Require ((Json (Field $parsed $entry.Name)) -ceq (Json $entry.Value)) ('JSON mismatch: ' + $case.id + '/' + $entry.Name)
            }
            foreach ($entry in $sets.PSObject.Properties) {
                $value = Field $parsed $entry.Name
                $keys = if ($value -is [pscustomobject]) { @($value.PSObject.Properties.Name) } else { @($value) }
                Require (@(Compare-Object -ReferenceObject @($entry.Value) -DifferenceObject $keys -CaseSensitive).Count -eq 0) ('Set mismatch: ' + $case.id)
            }
        }
        foreach ($path in (Optional $case 'files_exist' @())) { Require (Test-Path -LiteralPath (Inside $work $path) -PathType Leaf) ('Missing output: ' + $path) }
        foreach ($path in (Optional $case 'files_absent' @())) { Require (-not (Test-Path -LiteralPath (Inside $work $path))) ('Unexpected output: ' + $path) }
        foreach ($pattern in (Optional $case 'absent_globs' @())) { Require (@(Get-ChildItem -LiteralPath $work -Filter $pattern).Count -eq 0) 'Dry-run wrote a manifest.' }
        foreach ($pair in (Optional $case 'equal_files' @())) { Require ((Hash (Inside $work $pair[0])) -ceq (Hash (Inside $work $pair[1]))) 'Repair outputs differ.' }
        $count = Optional $case 'jsonl_success' $null
        if ($null -ne $count) {
            $responses = @($output -split '\r?\n' | Where-Object { $_.Length } | ForEach-Object { $_ | ConvertFrom-Json })
            Require ($responses.Count -eq $count) 'MCP response count mismatch.'
            foreach ($response in $responses) { Require ($null -ne $response.PSObject.Properties['result'] -and $null -eq $response.PSObject.Properties['error']) 'MCP request failed.' }
            Require ($responses[-1].result.isError -eq $false) 'MCP check failed.'
        }
        $outputs[$case.id] = $output
        $receipt.checks += [ordered]@{ id = $case.id; command = $case.args; exit_code = $exitCode }
    }
    foreach ($name in $before.Keys) { Require ((Hash (Inside $work ('examples/' + $name))) -ceq $before[$name]) 'Source mutated.' }
    $receipt.source_immutable = $true
    $receipt.status = 'PASS'
    Write-Output 'PASS: 32 CLI cases; clean-machine qualification requires separate evidence.'
}
catch {
    $receipt.error = $_.Exception.Message
    throw
}
finally {
    [IO.File]::WriteAllText($ReceiptPath, (ConvertTo-Json -InputObject $receipt -Depth 100) + "`n", $utf8)
}
