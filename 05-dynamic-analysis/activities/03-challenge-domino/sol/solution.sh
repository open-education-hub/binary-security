#!/bin/bash

# value needs to 33556737

echo "33556737" > payload
cat payload - | ./sppb
rm payload
