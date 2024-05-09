function Test-PlatformSupport {
    [cmdletbinding()]
    param
    (
		[System.String]
		$Type,
        [Parameter(Mandatory)]
        [ValidateSet('Core', 'Linux', 'MacOS', 'Windows', 'Windows:Desktop')]
        [System.String[]]
        $Support
    )
	$Supported=$false
    $os = Get-OSEnvironment
    # Check for PS5 Desktop Support
	if ($psEdition -eq 'Desktop')
	{
		# This will only run if the Supported Platform is Windows:Desktop
		$Supported= $Support -contains 'Windows'
	}
    # Check for PS Core and OS Support
    if ($psEdition -eq 'Core')
    {
        foreach ($supportEntry in $Support)
        {
            if ($supportEntry -eq 'core')
            {
                $Supported=$true
            }
            else
            {
                if ($supportEntry -eq $os)
                {
                    $Supported=$true
                }
            }
        }
    }
    return $Supported
}