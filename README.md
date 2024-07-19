# WinSocket

## g++ -shared -o WinSocket.dll WinSocket.cpp WinSocket.def -lws2_32 -static-libgcc -static-libstdc++ -DWIN32_LEAN_AND_MEAN -Os -s -fdata-sections -ffunction-sections -flto -Wl,--gc-sections -static

## cl WinSocket.cpp /Fe:WinSocket.dll /Ot /MT -DWIN32_LEAN_AND_MEAN /link /DLL /DEF:WinSocket.def 群友Fox提供
