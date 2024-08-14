rm -r out
cmake -DCMAKE_BUILD_TYPE=Release -DIdaSdk_ROOT_DIR=/Users/tom_rus/Desktop/idasdk90 -B out
cmake --build out
zip -j openlumina_mac.zip out/OpenLumina*.dylib
cp out/OpenLumina64.dylib "/Applications/IDA Freeware 8.4/ida64.app/Contents/MacOS/plugins/"
