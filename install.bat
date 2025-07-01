@echo off
REM Crée un protocole personnalisé "monapp://"

set PROTOCOL=monapp
set EXE_PATH="C:\Users\beric\Downloads\key\key.exe"

REM Créer les entrées dans le registre
reg add "HKEY_CLASSES_ROOT\%PROTOCOL%" /ve /d "URL:%PROTOCOL% Protocol" /f
reg add "HKEY_CLASSES_ROOT\%PROTOCOL%" /v "URL Protocol" /d "" /f
reg add "HKEY_CLASSES_ROOT\%PROTOCOL%\shell\open\command" /ve /d "%EXE_PATH% %%1" /f