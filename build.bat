@set OUT_DIR=output
@set OUT_CLIENT=client
@set OUT_SERVER=server
@set INCLUDES= /I .\ /I "%PROGRAMFILES%\OpenSSL-Win32\include" /I "%PROGRAMFILES%\OpenSSL-Win64\include"
@set SOURCES_CLIENT=network_client.cpp network_common.cpp client.cpp
@set SOURCES_SERVER=network_server.cpp network_common.cpp server.cpp
@set LIBS=/LIBPATH:"%PROGRAMFILES%\OpenSSL-Win32\lib" /LIBPATH:"%PROGRAMFILES%\OpenSSL-Win64\lib" libcrypto.lib libcrypto_static.lib libssl.lib libssl_static.lib
mkdir %OUT_DIR%
cl /nologo /Zi /EHsc /O2 /MD %INCLUDES% /D UNICODE /D _UNICODE %SOURCES_CLIENT% /Fe%OUT_DIR%/%OUT_CLIENT%.exe /Fo%OUT_DIR%/ /link %LIBS%
cl /nologo /Zi /EHsc /O2 /MD %INCLUDES% /D UNICODE /D _UNICODE %SOURCES_SERVER% /Fe%OUT_DIR%/%OUT_SERVER%.exe /Fo%OUT_DIR%/ /link %LIBS%
@copy *.pem %OUT_DIR%