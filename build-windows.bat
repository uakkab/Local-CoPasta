@echo off
REM Build script for Windows - No CGO required

echo Building Local Pastebin for Windows...
echo.

REM Clean any previous builds
if exist pastebin.exe del pastebin.exe

REM Update dependencies
echo Updating dependencies...
go mod tidy

REM Build the binary
echo Building binary...
go build -o pastebin.exe main.go

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ✓ Build successful!
    echo Binary created: pastebin.exe
    echo.
    echo To run the application:
    echo   .\pastebin.exe
    echo.
    echo The server will start on http://localhost:8080
) else (
    echo.
    echo ✗ Build failed. Please check the error messages above.
    exit /b 1
)
