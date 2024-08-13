@echo off
cmake -DCMAKE_BUILD_TYPE=Release -DIdaSdk_ROOT_DIR=e:\ida90\idasdk90 -B out
cmake --build out --config Release
rem cp out/OpenLumina64.so /home/tom_rus/idafree-8.4/plugins/
