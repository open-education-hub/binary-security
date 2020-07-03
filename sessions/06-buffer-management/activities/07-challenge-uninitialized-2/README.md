Vulnerability
------------------

  A local variable of a function is not initialized and it is used as an offset.


Exploit
------------------

  Overwrite the local variable from the caller by modifying what will be the callee's stack frame.

  Solution script in ./sol/exploit.py and ./sol/exploit.sh
