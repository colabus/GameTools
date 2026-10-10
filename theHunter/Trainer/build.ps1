$ErrorActionPreference = 'Stop'
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
& $compiler /nologo /target:winexe /platform:x64 /optimize+ "/win32icon:$PSScriptRoot\trainer.ico" "/resource:$PSScriptRoot\trainer.ico,TrainerIcon" "/out:$PSScriptRoot\theHunter Trainer by colabus.exe" /r:System.Windows.Forms.dll /r:System.Drawing.dll "$PSScriptRoot\Program.cs"
if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
Write-Output 'Built theHunter Trainer by colabus.exe (Windows x64, .NET Framework 4.x).'


& $compiler /nologo /target:exe /platform:x64 /optimize+ "/win32icon:$PSScriptRoot\trainer.ico" "/resource:$PSScriptRoot\trainer.ico,TrainerIcon" "/out:$PSScriptRoot\SuperSpeed-Diagnostics-v8.exe" /r:System.Windows.Forms.dll /r:System.Drawing.dll "$PSScriptRoot\Program.cs"
if ($LASTEXITCODE -ne 0) { throw "Diagnostics build failed." }



