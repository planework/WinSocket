@echo off
@g++ -shared -o WinSocket.eso WinSocket.cpp -static -lws2_32 -O2 -s -Wl,--kill-at,--enable-stdcall-fixup