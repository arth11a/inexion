@echo off
setlocal
cd /d "%~dp0"
set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY where python >nul 2>nul && set "PY=python"
if not defined PY goto nopython
if "%INX_PEER%"=="" set "INX_PEER=https://inexion.org"
if "%INX_NODE%"=="" set "INX_NODE=http://127.0.0.1:9333"
set "CMD=%~1"
if /i "%CMD%"=="wallet" goto wallet
if /i "%CMD%"=="node" goto node
if /i "%CMD%"=="mine" goto mine
if /i "%CMD%"=="balance" goto balance
echo INEXION test network
echo   inx wallet new --file wallet.json   create a wallet (password + recovery code)
echo   inx node                            run a node (downloads the chain from https://inexion.org)
echo   inx mine INX_ADDRESS                mine to your address (node must be running)
echo   inx balance --file wallet.json      show balance
goto :eof
:wallet
shift
%PY% wallet.py %1 %2 %3 %4 %5 %6 %7 %8 %9
goto :eof
:node
%PY% node.py --genesis testnet.json --datadir data --peer %INX_PEER%
goto :eof
:mine
if "%~2"=="" (echo Usage: inx mine INX_ADDRESS & goto :eof)
%PY% miner_fast.py --node %INX_NODE% --address %~2
goto :eof
:balance
shift
%PY% wallet.py balance --node %INX_NODE% %1 %2 %3 %4 %5 %6 %7 %8 %9
goto :eof
:nopython
echo Python 3 was not found. Install it with:  winget install Python.Python.3.12
echo Then close this window and run inx.bat again.
pause
exit /b 1
