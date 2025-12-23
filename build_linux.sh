rm -r out
cmake -DCMAKE_BUILD_TYPE=Release -DIdaSdk_ROOT_DIR=/home/tom_rus/idasdk91 -DIDA_90_STABLE=1 -B out
cmake --build out
zip -j openlumina_linux.zip out/OpenLumina*.so
#cp out/OpenLumina64.so /home/tom_rus/idafree-8.4/plugins/
