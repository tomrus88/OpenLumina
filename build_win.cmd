@echo off
rmdir /S /Q out
cmake -DCMAKE_BUILD_TYPE=Release -DIdaSdk_ROOT_DIR=e:\ida84\idasdk_pro84 -B out
cmake --build out --config Release
rem cp out/OpenLumina64.so /home/tom_rus/idafree-8.4/plugins/
