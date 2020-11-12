# mutation fuzzer

Written in C and based on Charlie Miller's ([@0xcharlie](https://twitter.com/0xcharlie)) presentation: *Babysitting an Army of Monkeys*. This program can help identify exploit candidates triggered by vulnerable binaries.

# usage

Post Reconnaissance:

```bash
$ gcc -o mutate main.c
$ ./mutate xxx.jpg
$ ./jpg2bmp /tmp/tmpVvzotD xxx.bmp
Segmentation fault (core dumped)
```
