@{
    PSDependOptions = @{
        Target = '$DependencyFolder\Dependencies'
        AddToPath = $true
    }

    'Pester' = '4.10.1'
    'BuildHelpers' = '2.0.16'
    'powershell-yaml' = '0.4.3'
    'PSPx' = '1.4.1'
    'PSTerraformLike' = '1.0.1.20231210'
    'NTObjectManager' = '2.0.1'
    'PowerShellNotebook' = '3.0.0'

    # Clone a git repo
    'https://github.com/kgkzworld/PSPortable_7.3.0' = 'main'
    'https://github.com/kgkzworld/PyPortable_3.10.11' = 'main'

    # Download a file
    #'psrabbitmq.dll' = @{
    #    DependencyType = 'FileDownload'
    #    Source = 'https://github.com/RamblingCookieMonster/PSRabbitMq/raw/master/PSRabbitMq/lib/RabbitMQ.Client.dll'
    #}
}