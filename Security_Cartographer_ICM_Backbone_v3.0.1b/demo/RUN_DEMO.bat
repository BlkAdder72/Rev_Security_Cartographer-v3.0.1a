@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 run_demo.py
) else (
  python run_demo.py
)
if errorlevel 1 (
  echo.
  echo The demonstration did not finish successfully.
  pause
  exit /b 1
)
echo.
echo Demonstration complete. Open demo_output\02-blocked-change\map.html
pause

