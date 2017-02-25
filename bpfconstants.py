def get_bpf_class(opcode):
    return code & 0x07

BPF_LD = 0x00
BPF_LDX = 0x01
BPF_ST = 0x02
BPF_STX = 0x03
BPF_ALU= 0x04
BPF_JMP = 0x05
BPF_RET = 0x06
BPF_MISC = 0x07
BPF_CLASS_LOOKUP = {
    BPF_LD : 'ld',
    BPF_LDX : 'ldx',
    BPF_ST : 'st',
    BPF_STX : 'stx',
    BPF_JMP : 'jmp',
    BPF_RET : 'ret',
    BPF_MISC : 'misc'
    }
def get_bpf_size(opcode):
    return opcode & 0x18

BPF_W = 0x00
BPF_H = 0x08
BPF_B = 0x10

def get_bpf_mode(opcode):
    return opcode & 0xe0

BPF_IMM = 0x00
BPF_ABS = 0x20
BPF_IND = 0x40
BPF_MEM	= 0x60
BPF_LEN	= 0x80
BPF_MSH	= 0xa0
load_optree = {
    'ld' : (BPF_LD, [BPF_ABS, BPF_IND, BPF_MEM, BPF_IMM, BPF_LEN]),
    'ldh' : (BPF_LD | BPF_H, [BPF_ABS, BPF_IND]),
    'ldb' : (BPF_LD | BPF_B, [BPF_ABS, BPF_IND]),
    'ldx' : (BPF_LDX, [BPF_MEM, BPF_IMM, BPF_MSH, BPF_LEN]),
    'ldxb' : (BPF_LDX | BPF_B, [BPF_MSH])
    }
def get_bpf_op(opcode):
    return code & 0xf0
BPF_ADD = 0x00
BPF_SUB = 0x10
BPF_MUL = 0x20
BPF_DIV = 0x30
BPF_OR = 0x40
BPF_AND = 0x50
BPF_LSH = 0x60
BPF_RSH = 0x70
BPF_NEG = 0x80
BPF_ALU_LOOKUP = {
    BPF_ADD : 'add',
    BPF_SUB : 'sub',
    BPF_MUL : 'mul',
    BPF_DIV : 'div',
    #BPF_MOD : 'mod',
    BPF_NEG : 'neg',
    BPF_AND : 'and',
    BPF_OR  : 'or',
    #BPF_XOR : 'xor',
    BPF_LSH : 'lsh',
    BPF_RSH : 'rsh',
    }


BPF_JA = 0x00
BPF_JEQ = 0x10
BPF_JGT = 0x20
BPF_JGE = 0x30
BPF_JSET= 0x40
BPF_JC_LOOKUP = {
    BPF_JEQ  : 'jeq',
    BPF_JGT  : 'jgt',
    BPF_JGE  : 'jge',
    BPF_JSET : 'jset',
}

#define BPF_SRC(code)	((code) & 0x08)
def get_bpf_src(opcode):
    return code & 0x08
BPF_K = 0x00
BPF_X = 0x08

def get_bpf_rval(opcode):
    #ret - BPF_K and BPF_X also apply */
    return code & 0x18

BPF_A = 0x10
