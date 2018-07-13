# CollectorCC

## Environment
* The *libmnl* should be installed.
  - i.e.) sudo apt-get install libmnl0 libmnl-dev
* Linux kernel 4.14
* TCP BBRX is already installed.

## Build
* make
* If the kernel header files are correctly installed `(sock_diag.h, inet_diag.h)`,
 `-D_CUSTOM_DIAG_HEADER__` in the Makefile can be removed.

## Usage
* -l: With this option, the program would print one json object per line.
      Without this option (default), the program would print one json per
      line, but each of these objects are in one big json array. So when the
      program is stopped (i.e. User type in Ctrl-C), the program would print
      "]" at the end. This is added by the signal handler.
* -w: With this option, the program would write output to the designated
      file. The path to the file should be passed with this option.
* -h: Prints usage of the program

### Examples
    ./collectorCC
    ./collectorCC -l
    ./collectorCC -w output.txt
    ./collectorCC -h
