New-Item -ItemType Directory -Path ..\dist -Force
Get-ChildItem ..\src\ | Copy-Item -Destination ..\dist\ -Container -Recurse -Filter *.html -Force