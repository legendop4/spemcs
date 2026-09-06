@echo off
setlocal enableextensions
pushd "%~dp0"
echo ============================================================
echo Running SPEMCS Student VM E2E Validation...
echo Working directory: %CD%
echo ============================================================

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& { Set-ExecutionPolicy Bypass -Scope Process -Force; & '.\Endpoint-agent\scripts\student_vm_e2e_validate.ps1' -MsiPath '.\Endpoint-agent\installer\dist\Spemcs.Agent.Setup.msi' -ReportPath '.\vm_validation_report.json' }"

echo ============================================================
echo Validation complete. Press any key to close.
echo ============================================================
popd
pause
