#!/usr/bin/python
from bcc import BPF

b = BPF(src_file='probe.c')

print("Probe loaded")
b.trace_print()
