function Get-OSEnvironment
{
    if ($PSVersionTable.PSEdition -eq 'Desktop')
    {
        return 'Windows'
    }
    elseif ($PSVersionTable.PSEdition -eq 'Core')
    {
        if ($IsLinux)
        {
            return 'Linux'
        }
        if ($IsMacOS)
        {
            return 'MacOS'
        }
        if ($IsWindows)
        {
            return 'Windows'
        }
    }
}