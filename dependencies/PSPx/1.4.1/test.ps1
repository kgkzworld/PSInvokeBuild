# Clear-Host

# function New-MardownEntry {
#     param(
#         [ValidateSet('markdown', 'psscript')]
#         $type,
#         $text
#     )

#     [pscustomobject]@{Type = $type; Text = @($text) }
# }

# #$Path = 'D:\mygit\PSPx\examples\markdown.md'
# #$Path = 'D:\mygit\PSPx\__tests__\testMarkdownFiles\basicPSBlocks.md'
# $Path = 'D:\temp\test.md'
# $mdContent = [System.IO.File]::ReadAllLines($Path)

# $parsedMD = @()

# $newMarkdowEntry = $true
# $found = $false

# switch ($mdContent) {
#     { $_.Trim() -eq '```ps' -Or $_.Trim() -eq '```ps1' -Or $_.Trim() -eq '```powershell' } {
#         $parsedMD += New-MardownEntry "PSScript" ("{0}" -f $_)
#         $found = $true
#         continue
#     }
    
#     { $_.StartsWith('```') } { 
#         $found = $false 
#         $parsedMD[-1].Text += "{0}" -f $_
#         $newMarkdowEntry = $true
#         continue
#     }
    
#     default {
#         if ($found -eq $true) {
#             $parsedMD[-1].Text += "{0}" -f $_
#         }
#         else {
#             if ($newMarkdowEntry -eq $true) {
#                 $parsedMD += New-MardownEntry "Markdown"
#                 $newMarkdowEntry = $false                
#             }
#             $parsedMD[-1].Text += "{0}" -f $_
#         }
#     }
# }

# function Get-PSScript {
#     param(
#         $parsedMarkdown
#     )

#     $parsedMarkdown | Where-Object type -eq 'psscript' | 
#     ForEach-Object { 
#         $end = $_.Text.Count - 2
#         $_.Text[1..$end]
#     }
# }

# function Update-MarkdownCodeFormatting {
#     param(
#         $parsedMarkdown
#     )

#     switch ($parsedMarkdown) {
#         { $_.Type -eq 'markdown' } {
#             continue 
#         }
#         { $_.Type -eq 'psscript' } {
#             $end = $_.Text.Count - 2
#             $s = $_.Text[1..$end] -join "`n"
#             $s = Invoke-Formatter -ScriptDefinition $s

#             $_.Text = "{0}`n{1}`n{2}" -f $_.Text[0], $s, $_.Text[-1]
#             continue 
#         }
#     }
# } 

# Update-MarkdownCodeFormatting $parsedMD
# $parsedMD.text > 'D:\temp\test-upd.md'