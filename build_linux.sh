cmake -DCMAKE_BUILD_TYPE=Release -DIdaSdk_ROOT_DIR=/home/tom_rus/idasdk90 -B out
cmake --build out
cp out/OpenLumina64.so /home/tom_rus/idafree-8.4/plugins/
