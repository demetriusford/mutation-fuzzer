# mutation fuzzer

Written in C and based on Charlie Miller's ([@0xcharlie](https://twitter.com/0xcharlie)) presentation: *Babysitting an Army of Monkeys*. This program can help identify exploit candidates triggered by vulnerable binaries.

# usage

Post Reconnaissance:

```bash
$ make
==> Checking for required commands...
==> Building jpg2bmp...
==> Building fuzzer...
==> Build complete!
$ ./fuzzer cross.jpg
Mutated file created: /tmp/fuzz_h1P2IO
$ ./jpg2bmp /tmp/fuzz_h1P2IO cross.bmp
Bug #4 triggered.
Segmentation fault (core dumped)
```

Using [@jfoote](https://github.com/jfoote/)'s exploitable GDB plugin to gauge likelihood:

```gdb
$ gdb --args ./jpg2bmp /tmp/tmpB3WZIc cross.bmp
(gdb) r
Starting program: /home/demetrius-ford/pentest/mutation-fuzzer/jpg2bmp /tmp/tmpB3WZIc cross.bmp
Bug #4 triggered.

Program received signal SIGSEGV, Segmentation fault.
0x00000000bffbffff in ?? ()
(gdb) exploitable
Description: Segmentation fault on program counter
Short description: SegFaultOnPc (3/22)
Hash: f6c31a70445b50c017eeaa1782b7be34.a02275b2f33a68c806d7551b0ba98206
Exploitability Classification: EXPLOITABLE
Explanation: The target tried to access data at an address that matches the program counter. This is likely due to the execution of a branch instruction (ex: 'call') with a bad argument, but it could also be due to execution continuing past the end of a memory region or another cause. Regardless this likely indicates that the program counter contents are tainted and can be controlled by an attacker.
Other tags: AccessViolation (21/22)
```
