#!/bin/bash

echo "Moving config to project directory"

cp ./config-bng1.txt ./clab-sros-lab01/bng1/tftpboot/config.txt
cp ./config-bng2.txt ./clab-sros-lab01/bng2/tftpboot/config.txt
cp ./config-agg1.txt ./clab-sros-lab01/agg1/tftpboot/config.txt
cp ./config-agg2.txt ./clab-sros-lab01/agg2/tftpboot/config.txt
cp ./config-agg3.txt ./clab-sros-lab01/agg3/tftpboot/config.txt

echo "Copy completed"

