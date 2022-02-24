function Log-It() {
<#
.SYNOPSIS

Logs a message to stdout.

Author: Tobias Neitzel (@qtc_de)
License: GPLv3
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Log function used by PowerEnum. Prints the specified string to stdout
prefixed with the timestamp of the call.

.PARAMETER Msg

The message to log

.EXAMPLE

Log-It "Log this message :)"
#>
    Param (
        [Parameter(Position = 0)]
        [String]
        $Msg
    )
    $Date = Get-Date -Format "dd/MM/yyyy HH:mm:ss"
    Write-Host "[$Date] :: $Msg"
}

function Start-Watcher {
<#
.SYNOPSIS

Create a file system watcher.

Author: Tobias Neitzel (@qtc_de)
License: GPLv3
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Creates a file system watcher on the specified directory.
Optionally copies or moves modified files to a user specified
directory.

.PARAMETER Path

The file system path to create the watcher on. Must be a local
directory.

.PARAMETER Copy

Optional file system path to copy modified files to.

.PARAMETER Move

Optional file system path to move modified files to.

.PARAMETER Pattern

Optional file name pattern to watch for. Default is "*".

.PARAMETER Recursive

Whether to watch subdirectories too. Default is false.

.EXAMPLE

PS C:\Users\Carlos> Start-Watcher .\Desktop
[24/02/2022 07:42:58] :: Creating file system watcher.
[24/02/2022 07:42:58] :: Register event handlers.
[24/02/2022 07:42:58] :: Starting Watcher. Press Ctrl+C to stop watching.
[24/02/2022 07:43:03] :: C:\Users\Carlos\Desktop\New Text Document.txt was Created.
[24/02/2022 07:43:12] :: C:\Users\Carlos\Desktop\New Text Document.txt was renamed to C:\Users\Carlos\Desktop\Watcher-Test.txt.
[24/02/2022 07:43:16] :: Watcher removed.

.EXAMPLE

PS C:\Users\Carlos> Start-Watcher .\Desktop -Copy C:\Users\Carlos\Documents\ -Recursive
[24/02/2022 07:55:22] :: Creating file system watcher.
[24/02/2022 07:55:22] :: Register event handlers.
[24/02/2022 07:55:22] :: Starting Watcher. Press Ctrl+C to stop watching.
[24/02/2022 07:55:25] :: C:\Users\Carlos\Desktop\Internal\credentials.txt was Changed.
[24/02/2022 07:55:25] :: Copying C:\Users\Carlos\Desktop\Internal\credentials.txt to C:\Users\Carlos\Documents\
[24/02/2022 07:55:27] :: Watcher removed.
#>
    Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [Parameter()]
        [String]
        $Copy,

        [Parameter()]
        [String]
        $Move,

        [Parameter()]
        [String]
        $Pattern = "*",

        [Parameter()]
        [Switch]
        $Recursive
    )

    $Path = Resolve-Path $Path
    Log-It "Creating file system watcher."
    $Watcher = New-Object IO.FileSystemWatcher $Path, $Pattern -Property @{ 
        IncludeSubdirectories = $Recursive
        NotifyFilter = [IO.NotifyFilters]'FileName, LastWrite'
    }

    if ($PSBoundParameters.ContainsKey('Move')) {
        $PostProcessing = "Log-It `"Moving `$Path to $Move`";"
        $PostProcessing += "Move-Item `"`$Path`" '$Move';" 
    } elseif ($PSBoundParameters.ContainsKey('Copy')) {
        $PostProcessing = "Log-It `"Copying `$Path to $Copy`";"
        $PostProcessing += "Copy-Item -Recurse `"`$Path`" '$Copy';"
    }

    $Action = [ScriptBlock]::Create(@(
        '$Path = $Event.SourceEventArgs.FullPath;'
        '$OldPath = $Event.SourceEventArgs.OldFullPath;'
        '$ChangeType = $Event.SourceEventArgs.ChangeType;'
        'switch ($ChangeType)'
        '{'
        '   "Deleted" { Log-It "$Path was deleted."; return }'
        '   "Renamed" { Log-It "$OldPath was renamed to $Path."; return }'
        '   default { Log-It "$Path was $ChangeType." }'
        '}'
        "$PostProcessing"
    ))

    Log-It "Register event handlers."
    $Handlers = . {
        Register-ObjectEvent $Watcher -EventName Created -Action $Action
        Register-ObjectEvent $Watcher -EventName Changed -Action $Action
        Register-ObjectEvent $Watcher -EventName Deleted -Action $Action
        Register-ObjectEvent $Watcher -EventName Renamed -Action $Action
    }

    try {
        Log-It "Starting Watcher. Press Ctrl+C to stop watching."
        Wait-Event
    }
    
    finally {
        $Watcher.Dispose()
        Log-It "Watcher removed."
    }
}
