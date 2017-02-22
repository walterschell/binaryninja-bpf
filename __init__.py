from binaryninja.architecture import Architecture
import struct

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

BPF_W		0x00
BPF_H		0x08
BPF_B		0x10

def get_bpf_mode(opcode):
    return opcode & 0xe0

BPF_IMM = 0x00
BPF_ABS = 0x20
BPF_IND = 0x40
BPF_MEM	= 0x60
BPF_LEN	= 0x80
BPF_MSH	= 0xa0

def get_bpf_op(opcode):
    return code & 0xf0
BPF_ADD		0x00
BPF_SUB		0x10
BPF_MUL		0x20
BPF_DIV		0x30
BPF_OR		0x40
BPF_AND		0x50
BPF_LSH		0x60
BPF_RSH		0x70
BPF_NEG		0x80
BPF_ALU_LOOKUP = {
    BPF_ADD : 'add',
    BPF_SUB : 'sub',
    BPF_MUL : 'mul',
    BPF_DIV : 'div',
    BPF_MOD : 'mod',
    BPF_NEG : 'neg',
    BPF_AND : 'and',
    BPF_OR  : 'or',
    BPF_XOR : 'xor',
    BPF_LSH : 'lsh',
    BPF_RSH : 'rsh',
    }


BPF_JA		0x00
BPF_JEQ		0x10
BPF_JGT		0x20
BPF_JGE		0x30
BPF_JSET	0x40
BPF_JMP_LOOKUP = {
    BPF_JA   : 'jmp',
    BPF_JEQ  : 'jeq',
    BPF_JGT  : 'jgt',
    BPF_JGE  : 'jge',
    BPF_JSET : 'jset',
}

define BPF_SRC(code)	((code) & 0x08)
def get_bpf_src(opcode):
    return code & 0x08
BPF_K = 0x00
BPF_X = 0x08

def get_bpf_rval(opcode):
    #ret - BPF_K and BPF_X also apply */
    return code & 0x18

BPF_A = 0x10

def get_miscop(opcode):
    return opcode & 0xf8
BPF_TAX = 0x00
BPF_TXA = 0x80


class BPFInstruction:
    def __init__(self, instruction, addr = 0, little_endian = True):
        unpack_endian = '<'
        if not little_endian:
            unpack_endian = '>'
        unpack_str = unpack_endian + 'HBBI'
        self.opcode, self.jt, self.jf, self.k = \
            struct.unpack(unpack_str, instruction)
        self.addr = addr
    
    @property
    def opcode_class(self):
        return get_bpf_class(self.opcode)

    
    def decode(self):
        if self.opcode_class == 
    
    def decode_ld(self):
        result = 'ld'
        x = False
        if self.opcode_class == BPF_LDX:
            x = True
        if x:
            result += 'x'
        size = get_bpf_size(self.opcode)
        if size == BPF_H:
            result += 'h'
        elif size == BPF_B
            result += 'b'
        
        result += ' '
        mode = get_bpf_mode(self.opcode)
        if mode == BPF_IMM:
            result += '#0x%x' % self.k
        elif mode == BPF_ABS:
            result += '[0x%x]' % self.k
        elif mode == BPF_IND:
            result += '[x + 0x%x]' % self.k
        elif mode == BPF_MEM:
            result += 'M[0x%x]' % self.k
        elif mode == BPF_LEN:
            result += '4*([0x%x]&0xf)' % self.k
        elif mode == BPF_MSH:
            result += 'Extension'
        return result
    

    def decode_st(self):
        result = 'st'
        x = False
        if self.opcode_class == BPF_STX:
            x = True
        if x:
            result +='x'
        result += ' '
        result += 'M[0x%x]' % self.k
        return result
    def decode_alu(self):
        alu_op = get_bpf_op(self.opcode)
        result = BPF_ALU_LOOKUP[alu_op]
        result += ' '
        src = get_bpf_src(self.opcode)
        if src == BPF_X:
            result += 'x'
        elif src == BPF_K:
            result += '#0x%x' % self.k
        else:
            raise Exception('UNK Source for alu op')
        return result
    
    def decode_jmp(self):
        
        
          

class BPFArch:
    name = "BPF"
    