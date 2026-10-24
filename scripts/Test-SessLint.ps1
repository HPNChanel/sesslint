# T-12: offline Windows PowerShell 5.1 / PowerShell 7.5+ acceptance. No Python or admin required.
[CmdletBinding()]
param(
    [string]$PackageRoot,
    [Parameter(Mandatory = $true)][string]$ReceiptPath
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$utf8 = New-Object System.Text.UTF8Encoding($false)
# BEGIN json-date-guard
# PowerShell 6+ turns ISO-8601 strings read by ConvertFrom-Json into [DateTime], which would change
# the contract's --as-of arguments before they reach the CLI. -DateKind String (PowerShell 7.5+) keeps
# them exactly as written; Windows PowerShell 5.1 never converts them. PowerShell 6.0-7.4 can do
# neither, so refuse before touching anything instead of running the cases with altered arguments.
$JsonParams = @{}
if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')) { $JsonParams['DateKind'] = 'String' }
elseif ($PSVersionTable.PSVersion.Major -ge 6) {
    [Console]::Error.WriteLine('Test-SessLint.ps1 cannot run on PowerShell ' + $PSVersionTable.PSVersion + ': its ConvertFrom-Json rewrites ISO-8601 strings in the smoke contract. Use Windows PowerShell 5.1 (powershell.exe) or PowerShell 7.5 or newer.')
    exit 2
}
# END json-date-guard
# Windows PowerShell 5.1 leaves $PSScriptRoot empty inside a param() default under -File
# (GetFullPath then fails with "path is not of a legal form"); resolve it in the body instead.
if ([string]::IsNullOrEmpty($PackageRoot)) { $PackageRoot = $PSScriptRoot }
if ([string]::IsNullOrEmpty($PackageRoot)) { throw 'Cannot determine the package folder; pass -PackageRoot.' }
# Resolve against the caller's current location ($PWD), not the process directory that
# [IO.Path]::GetFullPath uses; the two differ after Set-Location in an already open window.
$PackageRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($PackageRoot)
$ReceiptPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ReceiptPath)
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
    return [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8) | ConvertFrom-Json @JsonParams
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
        if ($Object -is [System.Array]) {
            $Object = $Object[[int]$part]
            continue
        }
        $property = $Object.PSObject.Properties[$part]
        if ($null -eq $property) { throw "Missing result field: $Name" }
        $Object = $property.Value
    }
    return ,$Object
}
function Json($Value) { return ConvertTo-Json -InputObject $Value -Depth 100 -Compress }
function Require([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Snapshot([string]$Root) {
    return (@(Get-ChildItem -LiteralPath $Root -Recurse -Force | Sort-Object FullName | ForEach-Object {
        $relative = $_.FullName.Substring($Root.Length)
        if ($_.PSIsContainer) { 'D ' + $relative }
        else { 'F ' + $relative + ' ' + (Hash $_.FullName) + ' ' + $_.LastWriteTimeUtc.Ticks }
    }) -join "`n")
}
function Example-Hash([string]$Root) {
    # Every file below examples/, keyed by its relative path (examples/outcome/* included).
    $hashes = @{}
    Get-ChildItem -LiteralPath $Root -File -Recurse -Force | ForEach-Object { $hashes[$_.FullName.Substring($Root.Length)] = Hash $_.FullName }
    return $hashes
}
function Quote-Argument([string]$Value) {
    # Windows CommandLineToArgvW quoting, including quotes and trailing backslashes.
    return '"' + [regex]::Replace([regex]::Replace($Value, '(\\*)"', '$1$1\"'), '(\\+)$', '$1$1') + '"'
}

try {
    $manifest = Read-Json (Join-Path $PackageRoot 'windows-acceptance.json')
    Require ($manifest.schema_version -eq 1) 'Unsupported package manifest.'
    Require ($manifest.version -match '^\d+\.\d+\.\d+$') 'Invalid package version.'
    foreach ($required in @($manifest.binary, $manifest.starter_kit, 'Test-SessLint.ps1', 'START_HERE.md', 'kit/VERSION', 'kit/smoke-contract.json', 'kit/LICENSE', 'kit/NOTICE', 'kit/QUICKSTART.md', 'kit/VERIFYING.md', 'kit/TRIAGE.md', 'kit/OUTCOME.md', 'kit/examples/unsupported.txt', 'kit/examples/outcome/contract.json', 'kit/examples/outcome/source.csv', 'kit/examples/outcome/target_complete.json')) {
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
    Require ($contract.schema_version -eq 1 -and $contract.cases.Count -eq 42) 'Invalid smoke contract.'
    Require (@($contract.cases.id | Select-Object -Unique).Count -eq 42) 'Duplicate case IDs.'
    $receipt.contract_sha256 = Hash (Join-Path $work 'smoke-contract.json')
    foreach ($copy in $contract.copies) {
        $target = Inside $work $copy[1]
        [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target)) | Out-Null
        [IO.File]::Copy((Inside $work $copy[0]), $target, $false)
    }
    $examples = Join-Path $work 'examples'
    $before = Example-Hash $examples
    $isolated = @{}
    foreach ($key in @('HOME','USERPROFILE','CODEX_HOME','CLAUDE_CONFIG_DIR','APPDATA','LOCALAPPDATA','TEMP','TMP','XDG_CACHE_HOME')) {
        $path = Join-Path $work ('isolated/' + $key)
        [IO.Directory]::CreateDirectory($path) | Out-Null
        $isolated[$key] = $path
    }
    $outputs = @{}
    $codepageWarned = $false
    foreach ($original in $contract.cases) {
        $case = (Json $original).Replace('{work}', $work.Replace('\','/')).Replace('{version}', $manifest.version) | ConvertFrom-Json @JsonParams
        Require ($case.id -match '^[a-z0-9-]+$') 'Invalid case ID.'
        $noWrites = Optional $case 'no_writes' $false
        $unchanged = if ($noWrites) { Snapshot $work } else { $null }
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
            if ($key -match '^(PYTHON|COVERAGE|SESSLINT_)') { $info.EnvironmentVariables.Remove($key) }
        }
        foreach ($key in $isolated.Keys) { $info.EnvironmentVariables[$key] = $isolated[$key] }
        $info.EnvironmentVariables['PATH'] = Join-Path $env:SystemRoot 'System32'
        $info.EnvironmentVariables['NO_COLOR'] = '1'
        $process = New-Object Diagnostics.Process
        $process.StartInfo = $info
        # Windows PowerShell 5.1 (.NET Framework) has no ProcessStartInfo.StandardInputEncoding:
        # Process.Start builds StandardInput from the console input codepage. At codepage 65001
        # that encoding carries a BOM and Start() itself flushes it into the child's stdin, which
        # corrupts the first JSON-RPC line (-32700). Everything we send is ASCII (non-ASCII is
        # \u-escaped), so for the duration of Start() switch to an ASCII-compatible codepage and
        # restore the caller's afterwards.
        $previousInputEncoding = $null
        try {
            try { $current = [Console]::InputEncoding } catch { $current = $null }  # no console attached: nothing to switch
            if ($null -ne $current -and ($current.CodePage -eq 65001 -or $current.GetPreamble().Length -gt 0)) {
                $previousInputEncoding = $current
                try { [Console]::InputEncoding = [Text.Encoding]::GetEncoding(1252) }
                catch {
                    if (-not $codepageWarned) {
                        $codepageWarned = $true
                        Write-Warning 'Could not switch the console input code page away from UTF-8; the CLI may receive a byte-order mark at the start of stdin and MCP or hook cases may fail.'
                    }
                }
            }
            [void]$process.Start()
        }
        finally {
            if ($null -ne $previousInputEncoding) {
                try { [Console]::InputEncoding = $previousInputEncoding } catch { }
            }
        }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        # Belt and braces: write BOM-free bytes straight to the child's stdin stream, and close that
        # stream (not the StreamWriter, whose Close() can emit its preamble even for an empty input).
        $stdin = $process.StandardInput.BaseStream
        foreach ($message in (Optional $case 'stdin_jsonl' @())) {
            # ASCII JSON is also valid UTF-8; avoids legacy console stdin codepages.
            $line = [regex]::Replace((Json $message), '[^\x00-\x7F]', { param($m) '\u{0:x4}' -f [int][char]$m.Value })
            $bytes = $utf8.GetBytes($line + "`n")
            $stdin.Write($bytes, 0, $bytes.Length)
        }
        $stdin.Flush()
        $stdin.Close()
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
            $parsed = $output | ConvertFrom-Json @JsonParams
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
            $responses = @($output -split '\r?\n' | Where-Object { $_.Length } | ForEach-Object { $_ | ConvertFrom-Json @JsonParams })
            Require ($responses.Count -eq $count) 'MCP response count mismatch.'
            foreach ($response in $responses) { Require ($null -ne $response.PSObject.Properties['result'] -and $null -eq $response.PSObject.Properties['error']) 'MCP request failed.' }
            Require ($responses[-1].result.isError -eq $false) 'MCP check failed.'
        }
        if ($noWrites) { Require ((Snapshot $work) -ceq $unchanged) ('Command wrote to work directory: ' + $case.id) }
        $outputs[$case.id] = $output
        $receipt.checks += [ordered]@{ id = $case.id; command = $case.args; exit_code = $exitCode }
    }
    $after = Example-Hash $examples
    foreach ($name in $before.Keys) { Require ($after.ContainsKey($name) -and $after[$name] -ceq $before[$name]) 'Source mutated.' }
    $receipt.source_immutable = $true
    $receipt.status = 'PASS'
    Write-Output 'PASS: 42 CLI cases; clean-machine qualification requires separate evidence.'
}
catch {
    $receipt.error = $_.Exception.Message
    throw
}
finally {
    [IO.File]::WriteAllText($ReceiptPath, (ConvertTo-Json -InputObject $receipt -Depth 100) + "`n", $utf8)
}
