# value needs to be greater than 100, smaller than 323 and
# divisible with 13

echo "312" > payload
cat payload - | ./sppb
rm payload
