from binaryninja.architecture import Architecture
from binaryninja.lowlevelil import LowLevelILLabel, LLIL_TEMP
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.binaryview import BinaryView
from binaryninja.types import Symbol
from binaryninja.log import log_error
from binaryninja.enums import (BranchType, InstructionTextTokenType,
							LowLevelILOperation, LowLevelILFlagCondition, FlagRole, SegmentFlag, SymbolType)

import struct

InstructionNames = {}
InstructionIL = {}
InstructionFormatters = {}
InstructionInfoModders = {}
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
def get_pkt_data(il, offset, use_index = False, size=4):
    pkt_index = il.const(4, offset)
    if use_index:
        pkt_index = il.add(4, pkt_index, il.reg(4,'x'))
    return il.load(size, il.add(4, il.reg(4,'pkt'), pkt_index))

def get_mem_data(il, addr):
    return il.reg(4,'r%d' % addr)
    
def get_ip_header_size(il, offset):
    low_nibble = il.and_expr(4, 
        get_pkt_data(il, offset, False, 1),
        il.const(4, 0xf)
        )
    return il.mult(4, il.const(4,4), low_nibble)
ld_source_IL = {
    BPF_ABS : lambda il, instr : get_pkt_data(il, instr.k),
    BPF_IND : lambda il, instr : get_pkt_data(il, instr.k, True),
    BPF_MEM : lambda il, instr : get_mem_data(il, instr.k),
    BPF_IMM : lambda il, instr : il.const(4, instr.k),
    BPF_LEN : lambda il, instr : il.reg(4, 'len'),
    BPF_MSH : lambda il, instr : get_ip_header_size(il, instr.k)
    }
def TextToken(txt):
    return InstructionTextToken(InstructionTextTokenType.TextToken, txt)
def IntegerToken(num):
    return InstructionTextToken(InstructionTextTokenType.IntegerToken, '#0x%x' % num, value=num)
def SeperatorToken(txt = ","):
    return InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, txt)
def RegisterToken(txt):
    return InstructionTextToken(InstructionTextTokenType.RegisterToken, txt)
def AddressToken(num):
    return InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, '0x%x' % num, value=num)

source_formatters = {
    BPF_ABS : lambda instr: [TextToken('[0x%x]' % instr.k)],
    BPF_IND : lambda instr: [TextToken('[0x%x + x]' % instr.k)],
    BPF_MEM : lambda instr: [TextToken('M[0x%x' % instr.k)],
    BPF_IMM : lambda instr: [IntegerToken(instr.k)],
    BPF_LEN : lambda instr: [RegisterToken('len')],
    BPF_MSH : lambda instr: [TextToken('4*([0x%x]&0xf)' % instr.k)]
    }
dest_tuples = {
    BPF_LD : (4, 'a'),
    BPF_LDX : (4, 'x'),
    BPF_LD | BPF_H : (2, 'a'),
    BPF_LD | BPF_B : (1, 'a'),
    BPF_LDX | BPF_H : (2, 'x'),
    BPF_LDX | BPF_B : (1, 'x'),
}
def load_il(size, dest, src):
    return lambda il, instr: il.set_reg(size, dest, src(il, instr))
def init_load_ops():
    for opname in load_optree:
        op_base, op_modes = load_optree[opname]
        for op_mode in op_modes:
            full_opcode = op_base | op_mode
            InstructionNames[full_opcode] = opname
            size, dest = dest_tuples[op_base]
            src = ld_source_IL[op_mode]
            #InstructionIL[full_opcode] = load_il(size, dest, src)
            InstructionFormatters[full_opcode] = source_formatters[op_mode]
            
init_load_ops()

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
aluret_src_IL = {
    BPF_K : lambda il, instr: il.const(4, instr.k),
    BPF_A : lambda il, instr: il.reg(4, 'a'),
    BPF_X : lambda il, instr: il.reg(4, 'x')
}
aluret_src_formatters = {
    BPF_K : lambda instr: [IntegerToken(instr.k)],
    BPF_A : lambda instr: [RegisterToken('a')],
    BPF_X : lambda instr: [RegisterToken('x')],
    }
def ja_modder(iinfo, instr):
    iinfo.add_branch(BranchType.BranchAlways, instr.ja_target)
    
def jc_modder(iinfo, instr):
    iinfo.add_branch(BranchType.TrueBranch, instr.jt_target)
    iinfo.add_branch(BranchType.FalseBranch, instr.jf_target)

def ja_formatter(instr): 
    return [AddressToken(instr.ja_target)]
def jc_formatter(instr):
    return [IntegerToken(instr.k), SeperatorToken(), 
            AddressToken(instr.jt_target), SeperatorToken(),
            AddressToken(instr.jf_target)]

def valid_label(il, target):
    label = il.get_label_for_address(Architecture['BPF'], target)
    if label is not None:
        return label
    il.add_label_for_address(Architecture['BPF'], target)
    return valid_label(il, target)
def ja_il(il, instr):
    label = None
    label = valid_label(il, instr.ja_target)
    return il.goto(label)

def jc_il(il, instr, cond): 
    t = valid_label(il, instr.jt_target)
    f = valid_label(il, instr.jf_target)	
    return il.if_expr(cond, t, f)


def init_alu_ops():
    for alu_op in BPF_ALU_LOOKUP:
        name = BPF_ALU_LOOKUP[alu_op]
        for src in [BPF_K, BPF_X]:
            full_opcode = alu_op | src
            InstructionNames[full_opcode] = name
            InstructionFormatters[full_opcode] = aluret_src_formatters[src]
 
def get_ret_llil(src):
    def ret_llil(il, instr):
        if src == BPF_X:
            src_il = il.reg(4, 'x')
        if src == BPF_K:
            src_il = il.const(4, instr.k)
        il.append(il.set_reg(4, 'dummyret', src))
        return il.ret(il.reg(4, 'dummylr'))
def init_ret_ops():
    for ret_src in [BPF_K, BPF_X, BPF_A]:
        full_opcode = BPF_RET | ret_src
        InstructionNames[full_opcode] = 'ret'
        InstructionIL[full_opcode] = lambda il, instr: il.no_ret()
        InstructionFormatters[full_opcode] = aluret_src_formatters[ret_src]
        InstructionInfoModders[full_opcode] = get_ret_llil(ret_src)
init_ret_ops()

def get_je_llil(src):
    def je_llil(il, inst):
        src_il = aluret_src_IL[src](il, inst)
        cond = il.compare_equal(4,il.reg(4, 'a'), src_il)
        return jc_il(il, inst, cond)
    return je_llil

def get_jgt_llil(src):
    def jgt_llil(il, inst):
        src_il = aluret_src_IL[src](il, inst)
        cond = il.compare_unsigned_greater_than(4,il.reg(4, 'a'), src_il)
        return jc_il(il, inst, cond)
    return jgt_llil
    
def get_jge_llil(src):
    def jge_llil(il, inst):
        src_il = aluret_src_IL[src](il, inst)
        cond = il.compare_unsigned_greater_equal(4, il.reg(4, 'a'), src_il)
        return jc_il(il, inst, cond)
    return jge_llil

def get_jset_llil(src):
    def jset_llil(il, inst):
        src_il = aluret_src_IL[src](il, inst)
        cond = il.compare_not_equal(4, il.const(4, 0), il.and_expr(4, il.reg(4, 'a'),src_il))
        return jc_il(il, inst, cond)
    return jset_llil
BPF_JC_LLIL_GENERATORS = {
    BPF_JEQ : get_je_llil,
    BPF_JGT : get_jgt_llil,
    BPF_JGE : get_jge_llil,
    BPF_JSET : get_jset_llil
}            
    
def init_jmp_ops():
    full_opcode = BPF_JMP|BPF_JA
    name = 'jmp'
    InstructionInfoModders[full_opcode] = ja_modder
    InstructionFormatters[full_opcode] = ja_formatter
    InstructionIL[full_opcode] = ja_il
    
    for jmp_op in BPF_JC_LOOKUP:
        for src in [BPF_K, BPF_X]:
            name = BPF_JC_LOOKUP[jmp_op]
            full_opcode = BPF_JMP|jmp_op|src
            InstructionNames[full_opcode] = name
            InstructionInfoModders[full_opcode] = jc_modder
            InstructionFormatters[full_opcode] = jc_formatter
            InstructionIL[full_opcode] = BPF_JC_LLIL_GENERATORS[jmp_op](src)
            
init_jmp_ops()
def get_miscop(opcode):
    return opcode & 0xf8
BPF_TAX = 0x00
BPF_TXA = 0x80
BPF_MISC_LOOKUP = {
    BPF_TAX : 'tax',
    BPF_TXA : 'txa'
}

def empty_formatter(instr):
    return []
def init_misc_ops():
    for misc_op in [BPF_TAX, BPF_TXA]:
        name = BPF_MISC_LOOKUP[misc_op]
        full_opcode = BPF_MISC | misc_op
        InstructionNames[full_opcode] = name
        InstructionFormatters[full_opcode] = empty_formatter
init_misc_ops()

class BPFInstruction:
    def __init__(self, instruction, addr = 0, little_endian = True):
        unpack_endian = '<'
        if not little_endian:
            unpack_endian = '>'
        unpack_str = unpack_endian + 'HBBI'
        self.opcode, self.jt, self.jf, self.k = \
            struct.unpack(unpack_str, instruction)
        self.addr = addr
    def offset2addr(self, offset):
        return self.addr + 8 * (offset + 1)
    @property
    def jt_target(self):
        return self.offset2addr(self.jt)
    @property
    def jf_target(self):
        return self.offset2addr(self.jf)
    @property
    def ja_target(self):
        return self.offset2addr(self.k)
    
                
def get_instruction(data, addr):
        try:
            instr = BPFInstruction(data, addr)
            return (True, instr)
        except:
            return (False, None)
        return (False, None)
zero_count = 0
class BPFArch(Architecture):
    name = "BPF"
    address_size = 4
    default_int_size = 4
    max_instr_length = 8
    regs = {
        "a" : RegisterInfo("a", 4),
        "x" : RegisterInfo("x", 4),
        "m0" : RegisterInfo("m0", 4),
        "m1": RegisterInfo("m1", 4),
        "m2" : RegisterInfo("m2", 4),
        "m3" : RegisterInfo("m3", 4),
        "m4" : RegisterInfo("m4", 4),
        "m5" : RegisterInfo("m5", 4),
        "m6" : RegisterInfo("m6", 4),
        "m7" : RegisterInfo("m7", 4),
        "m8" : RegisterInfo("m8", 4),
        "m9" : RegisterInfo("m9", 4),
        "m10" : RegisterInfo("m10", 4),
        "m11" : RegisterInfo("m11", 4),
        "m12" : RegisterInfo("m12", 4),
        "m13" : RegisterInfo("m13", 4),
        "m14" : RegisterInfo("m14", 4),
        "m15" : RegisterInfo("m15", 4),
        "pkt" : RegisterInfo("pkt", 4),
        "len" : RegisterInfo("len", 4),
        "dummystack" : RegisterInfo("dummystack", 4),
        "dummyret" : RegisterInfo("dummyret", 4),
        "dummylr" : RegisterInfo("dummylr", 4),
        
    }
    #because I _must_ have a stack pointer. (BPF has no stack)
    stack_pointer = "dummystack"

    def perform_get_instruction_info(self, data, addr): 
        valid, instr = get_instruction(data, addr)
        result = InstructionInfo()
        if valid:
            result.length = 8
            if instr.opcode in InstructionInfoModders:
                InstructionInfoModders[instr.opcode](result, instr)
        return result
    
    def perform_get_instruction_text(self, data, addr):
        valid, instr = get_instruction(data, addr)
        if not valid:
            return ([], 0)
        if instr.opcode not in InstructionNames:
            return ([InstructionTextToken(InstructionTextTokenType.InstructionToken,"unk opcode 0x%x" % instr.opcode)], 8)
        tokens = []
        instr_name = InstructionNames[instr.opcode]
        tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, instr_name))
        formatter = InstructionFormatters[instr.opcode]
        extra_tokens = formatter(instr)
        if len(extra_tokens) > 0:
            tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, " ")] + extra_tokens
        return (tokens, 8)
    
    def perform_get_instruction_low_level_il(self, data, addr, il):
        global zero_count
        if addr == 0:
            zero_count += 1
        else:
            zero_count = 0
        if zero_count >= 3:
            il.finalize()
            raise Exception('Infinite loop')
        print 'Getting il at 0x%x' % addr
        num_instr = len(data) / 8
        num_instr = 1
        print 'Asking to decode %d bytes (%d instructions)' % (len(data), num_instr)
        for i in xrange(num_instr):
            valid, instr = get_instruction(data[i*8:(i+1)*8], addr + i*8)
            if not valid:
                print '*********** Tried an failed **********'
                return None
            if instr.opcode not in InstructionIL:
                print 'Adding il.unimplemented()'
                il.append(il.unimplemented())
            else:
                print 'Adding custom il'
                il_exp = InstructionIL[instr.opcode](il, instr)
                if il_exp is not None:
                    print 'appending: %s' % str(il_exp)
                    il.append(il_exp)
                else:
                    print 'Failed to generate il'
                    
        print 'Full IL Decode was successful'
        print 'Len(IL): %s' % len(il)
        return 8
        
        
class BPFView(BinaryView):
    name = "BPF"
    long_name = "BPF"
    def __init__(self, data):
        BinaryView.__init__(self, parent_view = data, file_metadata = data.file)
        self.platform = Architecture['BPF'].standalone_platform
        num_instr, = struct.unpack('I', self.parent_view.read(0,4))
        size = num_instr * 8
        self.add_auto_segment(0, size, 4, size, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable | SegmentFlag.SegmentExecutable)
    @classmethod
    def is_valid_for_data(self, data):
        return True
    def perform_is_executable(self):
        return True
    def perform_get_entry_point(self):
        return 0
    def init(self):
        self.add_entry_point(0)
        #self.add_function(0)
BPFArch.register()
BPFView.register()