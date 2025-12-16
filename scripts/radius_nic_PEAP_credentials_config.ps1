param (
    [string]$username,
    [string]$password,
    [string]$nicname,
    [string]$logfile
)

# Start Logging
Start-Transcript -Path $logfile -Append

try {
    Write-Output "===== Starting 802.1X UI Automation Script ====="
    Write-Output "Username: $username"
    Write-Output "Script started at $(Get-Date)"

    # Load Required Assemblies
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName UIAutomationClient

    Write-Output "Loaded UI Automation Assemblies"

    # Function: Send Keyboard Inputs
    function Send-Keys {
        param ([string[]]$keys)
        foreach ($key in $keys) {
            Start-Sleep -Milliseconds 500
            [System.Windows.Forms.SendKeys]::SendWait($key)
            Start-Sleep -Milliseconds 500
            Write-Output "Sent key: $key"
        }
    }

    # Helper: Find an AutomationElement with timeout
    function Find-ElementWithTimeout {
        param(
            [System.Windows.Automation.AutomationElement]$root,
            [System.Windows.Automation.TreeScope]$scope,
            [string]$name,
            [int]$timeoutSeconds = 20
        )

        $endTime = (Get-Date).AddSeconds($timeoutSeconds)
        $cond = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::NameProperty, $name)

        while ((Get-Date) -lt $endTime) {
            try {
                $elem = $root.FindFirst($scope, $cond)
            } catch {
                $elem = $null
            }
            if ($elem) { return $elem }
            Start-Sleep -Milliseconds 400
        }
        return $null
    }

    # Helper: get child window by name (uses Descendants scope, with timeout)
    function Get-ChildWindow {
        param(
            [System.Windows.Automation.AutomationElement]$parent,
            [string]$childName,
            [int]$timeoutSeconds = 20
        )

        if (-not $parent) { return $null }
        return Find-ElementWithTimeout -root $parent -scope ([System.Windows.Automation.TreeScope]::Descendants) -name $childName -timeoutSeconds $timeoutSeconds
    }

    # Function: Click Button via UI Automation with awaiting and failing after timeout
    function Click-Button {
        param (
            [string]$parentTitle,
            [string[]]$childTitles,
            [string]$buttonName,
            [int]$timeoutSeconds = 20
        )

        Write-Output "Searching for parent window: '$parentTitle' (timeout ${timeoutSeconds}s)"
        Start-Sleep -Milliseconds 300

        $root = [System.Windows.Automation.AutomationElement]::RootElement

        $parentWindow = Find-ElementWithTimeout -root $root -scope ([System.Windows.Automation.TreeScope]::Children) -name $parentTitle -timeoutSeconds $timeoutSeconds
        if (-not $parentWindow) {
            $msg = "Parent window '$parentTitle' not found within ${timeoutSeconds}s!"
            Write-Output $msg
            throw $msg
        }

        Write-Output "Found parent window: '$parentTitle'"
        Start-Sleep -Milliseconds 300

        $currentWindow = $parentWindow
        foreach ($childTitle in $childTitles) {
            if ($childTitle -ne "") {
                Write-Output "Navigating to child: '$childTitle' (timeout ${timeoutSeconds}s)"
                $currentWindow = Get-ChildWindow -parent $currentWindow -childName $childTitle -timeoutSeconds $timeoutSeconds
                if (-not $currentWindow) {
                    $msg = "Could not navigate to child window: '$childTitle' within ${timeoutSeconds}s!"
                    Write-Output $msg
                    throw $msg
                }
                Write-Output "Arrived at child: '$childTitle'"
                Start-Sleep -Milliseconds 250
            }
        }

        Write-Output "Looking for button: '$buttonName' (timeout ${timeoutSeconds}s)"
        $button = Find-ElementWithTimeout -root $currentWindow -scope ([System.Windows.Automation.TreeScope]::Descendants) -name $buttonName -timeoutSeconds $timeoutSeconds

        if (-not $button) {
            $msg = "Button '$buttonName' not found within ${timeoutSeconds}s!"
            Write-Output $msg
            throw $msg
        }

        Write-Output "Found button: '$buttonName', attempting to click..."
        $pattern = $null
        if ($button.TryGetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern, [ref]$pattern)) {
            try {
                $pattern.Invoke()
                Write-Output "Clicked button: '$buttonName'"
            } catch {
                $msg = "Invoke on button '$buttonName' threw an exception: $_"
                Write-Output $msg
                throw $msg
            }
        } else {
            # fallback: try SetFocus + SendKeys {ENTER}
            try {
                $button.SetFocus()
                Start-Sleep -Milliseconds 200
                [System.Windows.Forms.SendKeys]::SendWait("{ENTER}")
                Write-Output "Tried fallback click (SetFocus + ENTER) on '$buttonName'"
            } catch {
                $msg = "Button '$buttonName' could not be clicked and fallback failed: $_"
                Write-Output $msg
                throw $msg
            }
        }

        Start-Sleep -Milliseconds 300
    }

    Write-Output "Configuring credentials for 802.1X Profile for $nicname"

    # Open Network Connections UI
    Write-Output "Opening Network Connections UI"
    Start-Process "ncpa.cpl"
    Start-Sleep -Seconds 3

    Click-Button "Network Connections" @() "$nicname" 20
    Click-Button "$nicname Status" @() "Properties" 20
    Start-Sleep -Seconds 10
    Send-Keys @("^{TAB}")

    Click-Button "$nicname Status" @("$nicname Properties") "Additional Settings..." 20

    # Try to click "Save credentials" button, if not found try "Replace credentials"
    Write-Output "Looking for 'Save credentials' or 'Replace credentials' button"
    try {
        Click-Button "$nicname Status" @("$nicname Properties", "Advanced settings") "Save credentials" 20
        Write-Output "Found and clicked 'Save credentials' button"
    } catch {
        Write-Output "'Save credentials' button not found, trying 'Replace credentials'"
        try {
            Click-Button "$nicname Status" @("$nicname Properties", "Advanced settings") "Replace credentials" 20
            Write-Output "Found and clicked 'Replace credentials' button"
        } catch {
            $msg = "Neither 'Save credentials' nor 'Replace credentials' button found!"
            Write-Output $msg
            throw $msg
        }
    }

    Write-Output "Entering Username and Password"
    Send-Keys @("$username{TAB}", "$password", "{ENTER}")

    Click-Button "$nicname Status" @("$nicname Properties", "Advanced settings") "OK" 20
    Click-Button "$nicname Status" @("$nicname Properties") "OK" 20
    Click-Button "$nicname Status" @() "Close" 20
    Click-Button "Network Connections" @() "Close" 20

    Write-Output "===== Script Execution Completed at $(Get-Date) ====="

} finally {
    # Stop Logging (ensure closed even on failure)
    try { Stop-Transcript } catch {}
}
