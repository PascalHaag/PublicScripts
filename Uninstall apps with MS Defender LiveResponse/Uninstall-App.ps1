[CmdletBinding()]
param (
    [ArgumentCompleter({
            $path = "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads\ApplicationInfo.json"
            if (-not(Test-Path $path)) {
                $path = "$($PSScriptRoot)\ApplicationInfo.json"
            }
            if (-not(Test-Path $path)) { return }

            (Get-Content $path | ConvertFrom-Json).ApplicationName | ForEach-Object {
                if ($_ -match "\s") { "'$_'" }
                else { $_ }
            }
        })]
    [string[]]
    $AppName,

    [switch]
    $Ignore
)

$script:ApplicationDefinitionPath = "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads\ApplicationInfo.json"

#region functions
function Get-ApplicationInfo {
    param (
        [string]
        $AppName,

        [version]
        $MinVersion,

        [string]
        $AppVendor
    )

    $uninstallPaths = @(
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "Microsoft.PowerShell.Core\Registry::HKEY_USERS\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    
    foreach ($uninstallPath in $uninstallPaths) {
        Get-ItemProperty $uninstallPath | Where-Object {
            (
                ($_.DisplayName -match $AppName) -and
                ($_.Publisher -match $AppVendor) -and
                ($MinVersion -gt $_.DisplayVersion)
            )   
        }
    }
}

function Uninstall-Application {
    [CmdletBinding()]
    param(
        $AppRegInfo,

        $AppConfig,

        [switch]
        $IgnoreSignature
    )
    #region Validation of HKEY_User (trusted certificate of uninstaller in user-context)
    if (($AppRegInfo.PSParentPath -match "^Microsoft.PowerShell.Core\\Registry::HKEY_USERS") -and ($AppRegInfo.PSParentPath -notmatch "^Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE")) {
        Write-Verbose "Start: Validation of HKEY_User (trusted certificate of uninstaller in user-context)"
        if (
            (-not $AppConfig.UninstallString) -or
            (-not $AppConfig.CodeSigningSubject) -or
            ($AppRegInfo.UninstallString -notlike "*$($AppConfig.UninstallString)*")
        ) {
            Write-Error "Error uninstalling $($AppRegInfo.DisplayName) with version $($AppRegInfo.DisplayVersion): Uninstaller trust can not be established for app installed in user-mode."
            return
        }
        
        if (-not (Test-Path -Path $AppConfig.UninstallString)) {
            Write-Error "Error uninstalling $($AppRegInfo.DisplayName) with version $($AppRegInfo.DisplayVersion): Uninstaller not found!"
            return
        }

        $uninstallerSignature = Get-AuthenticodeSignature -FilePath $AppConfig.UninstallString
        if (
            (($uninstallerSignature.SignerCertificate.Subject -ne $AppConfig.CodeSigningSubject) -or 
            ($uninstallerSignature.Status -ne 'Valid')) -and 
            (-not $IgnoreSignature)
        ) {
            Write-Warning "Uninstaller signature subject $($uninstallerSignature.SignerCertificate.Subject) with status: $($uninstallerSignature.Status) with issuer $($uninstallerSignature.SignerCertificate.Issuer)."
            Write-Error "Error uninstalling $($AppRegInfo.DisplayName) with version $($AppRegInfo.DisplayVersion): Invalid signature of uninstaller. "
            return
        }

        $param = @()
        if ($AppConfig.Parameter) { $param = @($AppConfig.Parameter) }
        $executables = Get-Item $AppConfig.UninstallString 
        foreach ($executable in $executables) {
            if ($AppRegInfo.UninstallString -notlike "*$($executable.FullName)*") { continue }
            Write-Verbose "Uninstall executable: $($executable.FullName) with parameter $param"
            & $executable.FullName @param
            
            if (-not (Test-Path -Path $AppRegInfo.UninstallString) -and (Test-Path -Path $AppRegInfo.PSPath)) {
                Write-Verbose "Delete registry entry: Unintaller: $($executable.FullName) not found and registry entry still there."
                Remove-Item -Path $AppRegInfo.PSPath -Force -Recurse
            }
        }
        Write-Verbose "End: Validation of HKEY_User (trusted certificate of uninstaller in user-context)"
        return
    }
    #endregion

    #region Uninstallation of application

    Write-Verbose "Start: Uninstallation of application"
    Write-Verbose "$AppRegInfo"

    if ($AppRegInfo.DisplayName -match "Malwarebytes") {
        $mbUninstaller = Join-Path $AppRegInfo.InstallLocation "mbuns.exe"
        Write-Verbose "Uninstaller of Malwarebytes: $mbUninstaller"
        Invoke-Expression "& '$mbUninstaller' -uninstall -verysilent"
        Invoke-Expression "& '$mbUninstaller' /uninstall /verysilent"
        return
    }

    if ($AppRegInfo.QuietUninstallString) {
        Invoke-Expression "& $($AppRegInfo.QuietUninstallString)"
    }
    elseif ($AppRegInfo.UninstallString -match "msiexec.exe") {
        msiexec.exe /x $AppRegInfo.PSChildName /qn
    }
    elseif ($AppConfig.Parameter) {
        $param = @($AppConfig.Parameter)
        $executable = $AppRegInfo.UninstallString -replace '^"(.+?)".*$', '$1'
        Write-Verbose "Uninstall executable: $executable with parameter $param"
        & $executable @param

        if (-not (Test-Path -Path $executable) -and (Test-Path -Path $AppRegInfo.PSPath)) {
            Write-Verbose "Uninstaller $executable not found and registry entry $($AppRegInfo.PSPath) still exists. Registry entry will be deleted."
            Remove-Item -Path $AppRegInfo.PSPath -Force -Recurse
        }
    }
    else {
        Write-Verbose "$($AppRegInfo.UninstallString)"
        Invoke-Expression "& $($AppRegInfo.UninstallString)"
    }
    Write-Verbose "End: Uninstallation of application"
    #endregion
}
#endregion functions

#region main
if (-not(Test-Path $script:ApplicationDefinitionPath)) {
    $script:ApplicationDefinitionPath = "$($PSScriptRoot)\ApplicationInfo.json"
}
if (-not(Test-Path $script:ApplicationDefinitionPath)) {
    throw "$($script:ApplicationDefinitionPath) was not found, please ensure that ApplicationInfo.json is in the same folder of the script."
    return
}

$applicationInfos = Get-Content $script:ApplicationDefinitionPath | ConvertFrom-Json | Write-Output | Where-Object ApplicationName -In $AppName

foreach ($appConfig in $applicationInfos) {
    $regInfos = Get-ApplicationInfo -AppName $appConfig.ApplicationName -MinVersion $appConfig.MinimumVersion -AppVendor $appConfig.VendorName
    foreach ($regInfo in $regInfos) {
        Write-Verbose "Following application is shown in $regInfo"
        Uninstall-Application -AppRegInfo $regInfo -AppConfig $appConfig -IgnoreSignature:$Ignore
    }
}
#endregion main