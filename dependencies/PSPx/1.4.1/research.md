Creating README files is a pain, especially when it comes to writing code samples. Code gets out of date, authors get sloppy, details get omitted, etc. PSPx takes the pain out of this process.

With PSPx, your readers can trust your code blocks are runnable and that code output will be as-claimed.

- Validate the correctness of code embedded in Markdown
- Run code embedded in Markdown
- Ship code and Markdown together in harmony

<br/>
<br/>

|Link|Description|
|:--|:--|
|https://github.com/EclecticIQ/rundoc|A command-line utility that runs code blocks from documentation written in markdown.
|https://github.com/earldouglas/codedown | Codedown is a little utility to extract code blocks from Markdown files. Inspired by [literate Haskell](https://wiki.haskell.org/Literate_programming).|
|https://github.com/schneems/rundoc|This library allows you to "run" your docs and embed the code as well as results back into the documentation.
|https://github.com/jonschlinkert/gfm-code-blocks|Extract gfm (GitHub Flavored Markdown) fenced code blocks from a string.
|https://github.com/broofa/runmd|Run code blocks in your markdown and annotate them with the output.

# Why do this?

- Do you have a very long installation documentation for our project and need a quick way of testing it? 
- It is general purpose tool that can be used for multiple purposes like executing a tutorial documentation, using docs as a script, etc.

Collects fenced code blocks from input markdown file and executes them in same order as they appear in the file. 

Example of fenced code block in markdown file

```ps1
foreach($i in 1..10) {
    $i
}
```

PSPx recognizes the tags `ps`, `ps1`, and `powershell`.

Currently, PSPx collects all the code blocks and executes them as a single script.

# Run a markdown file
Execute code blocks in input.md file

```powershell
Invoke-ExecuteMarkdown input.md
```

# Run a markdown file from a Url

```powershell
$url = 'https://raw.githubusercontent.com/dfinke/PSPx/master/__tests__/testMarkdownFiles/basicPSBlocks.md'

Invoke-ExecuteMarkdown $url
```

## The output
```
Path   : https://raw.githubusercontent.com/dfinke/PSPx/master/__tests__/testMarkdownFiles/basicPSBlocks.md
Script : {"Hello World", "Goodbye", $xs = 1, 2, 3, foreach ($x in $xs) {ΓÇª}
Cmdlet : Invoke-ExecuteMarkdown
Result : {Hello World, Goodbye, 1, 2...}
```

# List Code Blocks

Wouldn't it be great to be able to list all code blocks that are going to be executed before actually using run command? You can! 
There are a couple of ways to do this.

This returns all of the code blocks as a single `Script`.

```powershell
Get-MarkdownCodeBlock basicPSBlocks.md
```

### Result
```
Path   : D:\mygit\PSPx\__tests__\testMarkdownFiles\basicPSBlocks.md
Script : {"Hello World", "Goodbye", $xs = 1, 2, 3, foreach ($x in $xs) {...}
```

## Use `-Raw` Switch

This returns both the markdown and code blocks from the target `.md` file. Each is tagged with a `Type` => `PSScript`|`Markdown`.

```powershell
Get-MarkdownCodeBlock basicPSBlocks.md -Raw
```

### Result

```
Type : PSScript
Text : {```ps, "Hello World", ```}
Path : D:\mygit\PSPx\__tests__\testMarkdownFiles\basicPSBlocks.md

Type : Markdown
Text : {$null, , # Another block, }
Path : D:\mygit\PSPx\__tests__\testMarkdownFiles\basicPSBlocks.md

Type : PSScript
Text : {```ps, "Goodbye", ```}
Path : D:\mygit\PSPx\__tests__\testMarkdownFiles\basicPSBlocks.md

Type : Markdown
Text : {$null, , # Add some numbers, }
Path : D:\mygit\PSPx\__tests__\testMarkdownFiles\basicPSBlocks.md

Type : PSScript
Text : {```ps, $xs = 1, 2, 3, foreach ($x in $xs) {,     $xΓÇª}
Path : D:\mygit\PSPx\__tests__\testMarkdownFiles\basicPSBlocks.md

Type : Markdown
Text : {$null, , # Return a string, use a powershell block, }
Path : D:\mygit\PSPx\__tests__\testMarkdownFiles\basicPSBlocks.md

Type : PSScript
Text : {```powershell, 'This is a powershell block', ```}
Path : D:\mygit\PSPx\__tests__\testMarkdownFiles\basicPSBlocks.md

Type : Markdown
Text : {$null, , # Add Numbers, }
Path : D:\mygit\PSPx\__tests__\testMarkdownFiles\basicPSBlocks.md

Type : PSScript
Text : {```ps1, 3+4+5, ```}
Path : D:\mygit\PSPx\__tests__\testMarkdownFiles\basicPSBlocks.md
```

This gives you the ability to process the mardown file on your own. For example, you can extract the PowerShell from the `Text` parameter like this.

```powershell
Get-MarkdownCodeBlock basicPSBlocks.md -Raw |
    Where Type -eq 'PSScript' | 
    ForEach { $_.Text[1..($_.Text.Count - 2)] }
```

