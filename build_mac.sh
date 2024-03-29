cmake -DIdaSdk_ROOT_DIR=/Users/tom_rus/Desktop/idasdk_pro84 -B out
cmake --build out
cp out/OpenLumina64.dylib "/Applications/IDA Freeware 8.4/ida64.app/Contents/MacOS/plugins/"
