# binaryninja-bpf
Plugin for BPF architecture
Use to dissassemble output of https://github.com/cloudflare/bpftools
Save the output (single line of numbers) to a text file and open it in Binary Ninja with this plugin in your plugins dir.
If it parsed successfully, you will see a xt_bpf view. There is a regular BPF view to be used with instructions already in native form. It has a 4 byte header with the number of instructions followed by the instructions.
```
$ ./bpfgen  dns_validate -- --strict
20,0 0 0 0,177 0 0 0,12 0 0 0,7 0 0 0,72 0 0 4,53 0 13 29,135 0 0 0,4 0 0 8,7 0 0 0,72 0 0 2,84 0 0 65423,21 0 7 0,72 0 0 4,21 0 5 1,64 0 0 6,21 0 3 0,72 0 0 10,37 1 0 1,6 0 0 0,6 0 0 65535,
$ ./bpfgen  dns_validate -- --strict > ~/filter.txt && binaryninja filter.txt
```

```c
struct bpf_instruction {
  uint16_t opcode;
  uint8_t jt;
  uint8_t jf;
  uint32_t k;
};
struct bpf_file {
  uint32_t num_instructions;
  struct bpf_instruction instructions[];
};
```
