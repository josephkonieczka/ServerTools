@echo off
set folder=%~dp0
set scriptPath=%folder%server_tools.ps1
Powershell -NoProfile -ExecutionPolicy ByPass -Command "& '%scriptPath%'";

