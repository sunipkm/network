@set OUT_DIR=build
@set OUT_EXE=client
@set INCLUDES= /I .\ /I .\vclib
@set SOURCES=network_client.cpp network_common.cpp client_win32.cpp
@set LIBS=/LIBPATH:"vclib\" libcrypto.lib libcrypto_static.lib libssl.lib libssl_static.lib
mkdir %OUT_DIR%
cl /nologo /Zi /EHsc /O2 /MD %INCLUDES% /D UNICODE /D _UNICODE %SOURCES% /Fe%OUT_DIR%/%OUT_EXE%.exe /Fo%OUT_DIR%/ /link %LIBS%