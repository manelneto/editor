# Lab1 Report


## Programs chosen


The programs we chose to investigate were ```misused_string_fct_taint-bad.c``` and ```os_cmd_scope-bad.c```.


## CWE

The CWE present in ```misused_string_fct_taint-bad.c``` is CWE-121: Stack-based Buffer Overflow.
The CWE present in ```os_cmd_scope-bad.c``` is CWE-78: Improper Neutralization of Special Elements used in an OS Command.


## Tools used

The tools used to analyze ```misused_string_fct_taint-bad.c``` were Valgrind, due to it's usefulness in detecting stack smashing and stack overflow based vulnerabilities.
The tools used to analyze ```os_cmd_scope-bad.c``` were


## Using the tools

### ```misused_string_fct_taint-bad.c```

When using Valgrind to analyze this program, intially we tried using an input bellow 10, the program didn't identify any issues. We then decided to use the same command but with an input of more than 10. Valgrind was a ble to identify that there was stack smashing happening.

![input bellow 10] /images/ss1.png

![input above 10] /images/ss2.png

### ```os_cmd_scope-bad.c```
