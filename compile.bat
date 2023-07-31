@echo off

cl.exe /nologo /MT /W0 /TC ppid-spoof.c /link /OUT:ppid-spoof.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
del ppid-spoof.obj