@echo off
echo Windows build script for Endpoint Protection Platform
echo ===================================================

REM Clean build directory if it exists
if exist build (
    echo Cleaning build directory...
    rd /s /q build
)

REM Create new build directory
echo Creating build directory...
mkdir build
cd build

REM Configure with CMake
echo Running CMake configuration...
cmake -G "Visual Studio 17 2022" ..
if %errorlevel% neq 0 (
    echo CMake configuration failed!
    exit /b %errorlevel%
)

REM Build the project
echo Building project...
cmake --build . --config Release
if %errorlevel% neq 0 (
    echo Build failed!
    exit /b %errorlevel%
)

echo ===================================================
echo Build completed successfully!
echo Executable location: %cd%\Release\Endpoint_Protection_Platform.exe
echo ===================================================