<#
    .DESCRIPTION
        Pester Test File

    .EXAMPLE
        Command: Invoke-Pester -Path .\QuickPesterCheck.Tests.ps1
        Description: Quick test to show the general Output of a Pester Test
        Notes: Describe and It blocks can run from the ISE if Pester 4.10.1 is loaded.
            Context blocks need to be run under Invoke-Pester.

    .NOTES
        [Original Author]
            o Michael Arroyo
        [Original Build Version]
            o 1.0.0.20240129 (Major.Minor.Patch.Date<YYYYMMDD>)
        [Latest Author]
            o Michael Arroyo
        [Latest Build Version]
            o  1.0.0.20240129 (Major.Minor.Patch.Date<YYYYMMDD>)
        [Comments]
            o
        [PowerShell Compatibility / Tested On]
            o 5.x
        [Forked Project]
            o
        [Dependencies]
            o Pester / Version = '4.10.1'

    .LINK
#>

#region Build Notes
    <#
        [Build Version Details]
            o 1.0.0.20240129 -
                [Michael Arroyo] Intial Build
    #>
#endregion Build Notes

Context "[+] Running Context Section [Pester Test Processing]" {
    Describe "[+] Running Describe Section [Check Overall Process]" {
        It "Show Valid Process" {
            $true | Should -be $true
        }
    }

    Describe "[+] Running Describe Section [Check Overall Process]" {
        It "Show Invalid Process" {
            $false | Should -be $true
        }
    }
}