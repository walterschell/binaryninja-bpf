import struct

from binaryninja.architecture import Architecture
from binaryninja.binaryview import BinaryView
from binaryninja.enums import (BranchType, InstructionTextTokenType,
                               SegmentFlag)
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.lowlevelil import LowLevelILInstruction
from bpfconstants import *

# Opcode to instruction name mapping
InstructionNames = {}

# Opcode to il generator mapping
InstructionLLIL = {}

# Opcode to operand formatter mapping
InstructionFormatters = {}

# Opcode to InstructionInfo modder mapping
# Only used for control flow instruction
InstructionInfoModders = {}

# Attempt to construct IL for each class of instructions?
DO_RET_IL = True
DO_JMP_IL = True
DO_LD_IL = True
DO_ALU_IL = True
DO_MISC_IL = True
DO_STORE_IL = True


def get_pkt_data(il, offset, use_index=False, size=4):
    """
    Returns llil expression to get data from packet at offset
    :param il: llil function to generate expression with
    :param offset: packet offset to retrieve
    :param use_index: add the index register to offset if true
    :param size: number of bytes to retrieve
    :return: llil expression that will get data from packet at offset
    """
    pkt_index = il.const(4, offset)
    if use_index:
        pkt_index = il.add(4, pkt_index, il.reg(4, 'x'))
    return il.load(size, il.add(4, il.reg(4, 'pkt'), pkt_index))


def get_mem_data(il, addr):
    """
    Returns data at memory location addr
    :param il: llil function to generate expression with
    :param addr: memory addr to retrieve (Max is 15)
    :return: llil expression to access M[addr]
    """
    return il.reg(4, 'r%d' % addr)


def get_ip_header_size(il, offset):
    """
    Implements the BPF get header size load source
    :param il: llil function to generate expression with
    :param offset: offset of ip header
    :return: size of IP header located at offset in bytes
    """
    low_nibble = il.and_expr(4,
                             get_pkt_data(il, offset, False, 1),
                             il.const(4, 0xf)
                             )
    return il.mult(4, il.const(4, 4), low_nibble)


ld_source_IL = {
    BPF_ABS: lambda il, instr: get_pkt_data(il, instr.k),
    BPF_IND: lambda il, instr: get_pkt_data(il, instr.k, True),
    BPF_MEM: lambda il, instr: get_mem_data(il, instr.k),
    BPF_IMM: lambda il, instr: il.const(4, instr.k),
    BPF_LEN: lambda il, instr: il.reg(4, 'len'),
    BPF_MSH: lambda il, instr: get_ip_header_size(il, instr.k)
}


# These functions are wrappers for generating tokens for dissassembly
def TextToken(txt):
    return InstructionTextToken(InstructionTextTokenType.TextToken, txt)


def IntegerToken(num):
    return InstructionTextToken(InstructionTextTokenType.IntegerToken, '#0x%x' % num, value=num)


def SeperatorToken(txt=","):
    return InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, txt)


def RegisterToken(txt):
    return InstructionTextToken(InstructionTextTokenType.RegisterToken, txt)


def AddressToken(num):
    return InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, '0x%x' % num, value=num)


source_formatters = {
    BPF_ABS: lambda instr: [TextToken('['), IntegerToken(instr.k), TextToken(']')],
    BPF_IND: lambda instr: [TextToken('['), IntegerToken(instr.k), TextToken(' + '), RegisterToken('x'),
                            TextToken(']')],
    BPF_MEM: lambda instr: [TextToken('M['), IntegerToken(instr.k), TextToken(']')],
    BPF_IMM: lambda instr: [IntegerToken(instr.k)],
    BPF_LEN: lambda instr: [RegisterToken('len')],
    BPF_MSH: lambda instr: [TextToken('4*(['), IntegerToken(instr.k), TextToken(']&0xf)')]
}
dest_tuples = {
    BPF_LD: (4, 'a'),
    BPF_LDX: (4, 'x'),
    BPF_LD | BPF_H: (2, 'a'),
    BPF_LD | BPF_B: (1, 'a'),
    BPF_LDX | BPF_H: (2, 'x'),
    BPF_LDX | BPF_B: (1, 'x'),
}


def load_il(size, dest, src):
    """
    Returns a load il generator of appropriate size, destination and source
    :param size: size of load 4,2,1 bytes
    :param dest: destination a or x
    :param src: source of load, one of [BPF_ABS, BPF_IND, BPF_MEM, BPF_IMM, BPF_LEN, BPF_MSH]
    :return: llil expression generator that will return an expression setting the target register
    to the with the correct source and size
    """
    return lambda il, instr: il.set_reg(size, dest, src(il, instr))


def init_load_ops():
    """
    Wires up the load ops for disassembly, instruction info and llil
    :return: None
    """
    for opname in load_optree:
        op_base, op_modes = load_optree[opname]
        for op_mode in op_modes:
            full_opcode = op_base | op_mode
            InstructionNames[full_opcode] = opname
            size, dest = dest_tuples[op_base]
            src = ld_source_IL[op_mode]
            if DO_LD_IL:
                InstructionLLIL[full_opcode] = load_il(size, dest, src)
            InstructionFormatters[full_opcode] = source_formatters[op_mode]


init_load_ops()


def init_store_ops():
    """
    Wires up the store ops for disassembly, instruction info and llil
    :return:
    """
    InstructionNames[BPF_ST] = 'st'
    InstructionNames[BPF_STX] = 'stx'
    if DO_STORE_IL:
        InstructionLLIL[BPF_ST] = lambda il, instr: il.set_reg(4, 'm%d' % instr.k, il.reg(4, 'a'))
        InstructionLLIL[BPF_ST] = lambda il, instr: il.set_reg(4, 'm%d' % instr.k, il.reg(4, 'x'))


init_store_ops()
aluret_src_IL = {
    BPF_K: lambda il, instr: il.const(4, instr.k),
    BPF_A: lambda il, instr: il.reg(4, 'a'),
    BPF_X: lambda il, instr: il.reg(4, 'x')
}
aluret_src_formatters = {
    BPF_K: lambda instr: [IntegerToken(instr.k)],
    BPF_A: lambda instr: [RegisterToken('a')],
    BPF_X: lambda instr: [RegisterToken('x')],
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
    """
    Returns a garunteed valid llil label for an address
    :param il: llil function to generate label with
    :param target: address to generate label for
    :return: valid llil label for target
    """
    label = il.get_label_for_address(Architecture['BPF'], target)
    if label is not None:
        print 'label for 0x%x existed' % target
        return label
    print 'Adding label for 0x%x and trying again' % target
    il.add_label_for_address(Architecture['BPF'], target)
    return valid_label(il, target)


def ja_il(il, instr):
    """
    Returns llil expression to goto target of instruction
    :param il: llil function to generate expression with
    :param instr: instruction to pull jump target from
    :return: llil expression to goto target of instr
    """
    label = valid_label(il, instr.ja_target)
    return il.goto(label)


def jc_il(il, instr, cond):
    t = valid_label(il, instr.jt_target)
    f = valid_label(il, instr.jf_target)
    print 'jt(0x%x) Label Handle: %s' % (instr.jt_target, t.handle)
    print 'jf(0x%x) Label Handle: %s' % (instr.jf_target, f.handle)
    return il.if_expr(cond, t, f)


def get_add_llil(src):
    def add_llil(il, instr):
        return il.set_reg(4, 'a', il.add(4, il.reg(4, 'a'), src(il, instr)))

    return add_llil


def get_sub_llil(src):
    def sub_llil(il, instr):
        return il.set_reg(4, 'a', il.sub(4, il.reg(4, 'a'), src(il, instr)))

    return sub_llil


def get_mul_llil(src):
    def mul_llil(il, instr):
        return il.set_reg(4, 'a', il.mult(4, il.reg(4, 'a'), src(il, instr)))

    return mul_llil


def get_div_llil(src):
    def div_llil(il, instr):
        return il.set_reg(4, 'a', il.div_unsigned(4, il.reg(4, 'a'), src(il, instr)))

    return div_llil


def get_neg_llil(src):
    def neg_llil(il, instr):
        return il.set_reg(4, 'a', il.not_expr(4, il.reg(4, 'a')))

    return neg_llil


def get_and_llil(src):
    def and_llil(il, instr):
        return il.set_reg(4, 'a', il.and_expr(4, il.reg(4, 'a'), src(il, instr)))

    return and_llil


def get_or_llil(src):
    def or_llil(il, instr):
        return il.set_reg(4, 'a', il.or_exp(4, il.reg(4, 'a'), src(il, instr)))

    return or_llil


def get_lsh_llil(src):
    def lsh_llil(il, instr):
        return il.set_reg(4, 'a', il.shift_left(4, il.reg(4, 'a'), src(il, instr)))

    return lsh_llil


def get_rsh_llil(src):
    def sub_llil(il, instr):
        return il.set_reg(4, 'a', il.logical_shift_right(4, il.reg(4, 'a'), src(il, instr)))

    return sub_llil


def get_mod_llil(src):
    def mod_llil(il, instr):
        return il.set_reg(4, 'a', il.mod(4, il.reg(4, 'a'), src(il, instr)))

    return mod_llil


def get_xor_llil(src):
    def xor_llil(il, instr):
        return il.set_reg(4, 'a', il.xor_exp(4, il.reg(4, 'a'), src(il, instr)))

    return xor_llil


ALU_LLIL = {
    BPF_ADD: get_add_llil,
    BPF_SUB: get_sub_llil,
    BPF_MUL: get_mul_llil,
    BPF_DIV: get_div_llil,
    BPF_MOD: get_mod_llil,
    BPF_NEG: get_neg_llil,
    BPF_AND: get_and_llil,
    BPF_OR: get_or_llil,
    BPF_XOR: get_xor_llil,
    BPF_LSH: get_lsh_llil,
    BPF_RSH: get_rsh_llil,

}


def init_alu_ops():
    for alu_op in BPF_ALU_LOOKUP:
        name = BPF_ALU_LOOKUP[alu_op]
        for src in [BPF_K, BPF_X]:
            full_opcode = BPF_ALU | alu_op | src
            InstructionNames[full_opcode] = name
            InstructionFormatters[full_opcode] = aluret_src_formatters[src]
            InstructionLLIL[full_opcode] = ALU_LLIL[alu_op](aluret_src_IL[src])


init_alu_ops()


def get_ret_llil(src):
    def ret_llil(il, instr):
        if src == BPF_X:
            src_il = il.reg(4, 'x')
        if src == BPF_K:
            src_il = il.const(4, instr.k)
        ret_value_exp = il.set_reg(4, 'dummyret', src_il)
        print 'Appending: %s' % LowLevelILInstruction(il, ret_value_exp.index)
        il.append(ret_value_exp)
        return il.ret(il.reg(4, 'dummylr'))

    return ret_llil


def ret_modder(iinfo, instr):
    iinfo.add_branch(BranchType.FunctionReturn)


def init_ret_ops():
    for ret_src in [BPF_K, BPF_X, BPF_A]:
        full_opcode = BPF_RET | ret_src
        InstructionNames[full_opcode] = 'ret'
        if DO_RET_IL:
            InstructionLLIL[full_opcode] = get_ret_llil(ret_src)
        InstructionFormatters[full_opcode] = aluret_src_formatters[ret_src]
        InstructionInfoModders[full_opcode] = ret_modder


init_ret_ops()


def get_je_llil(src):
    def je_llil(il, inst):
        src_il = aluret_src_IL[src](il, inst)
        cond = il.compare_equal(4, il.reg(4, 'a'), src_il)
        return jc_il(il, inst, cond)

    return je_llil


def get_jgt_llil(src):
    def jgt_llil(il, inst):
        src_il = aluret_src_IL[src](il, inst)
        cond = il.compare_unsigned_greater_than(4, il.reg(4, 'a'), src_il)
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
        cond = il.compare_not_equal(4, il.const(4, 0), il.and_expr(4, il.reg(4, 'a'), src_il))
        return jc_il(il, inst, cond)

    return jset_llil


BPF_JC_LLIL_GENERATORS = {
    BPF_JEQ: get_je_llil,
    BPF_JGT: get_jgt_llil,
    BPF_JGE: get_jge_llil,
    BPF_JSET: get_jset_llil
}


def init_jmp_ops():
    full_opcode = BPF_JMP | BPF_JA
    name = 'jmp'
    InstructionInfoModders[full_opcode] = ja_modder
    InstructionFormatters[full_opcode] = ja_formatter
    if DO_JMP_IL:
        InstructionLLIL[full_opcode] = ja_il
    InstructionNames[full_opcode] = name

    for jmp_op in BPF_JC_LOOKUP:
        for src in [BPF_K, BPF_X]:
            name = BPF_JC_LOOKUP[jmp_op]
            full_opcode = BPF_JMP | jmp_op | src
            InstructionNames[full_opcode] = name
            InstructionInfoModders[full_opcode] = jc_modder
            InstructionFormatters[full_opcode] = jc_formatter
            if DO_JMP_IL:
                InstructionLLIL[full_opcode] = BPF_JC_LLIL_GENERATORS[jmp_op](src)


init_jmp_ops()


def empty_formatter(instr):
    return []


BPF_MISC_LLIL = {
    BPF_TAX: lambda il, instr: il.set_reg(4, 'x', il.reg(4, 'a')),
    BPF_TXA: lambda il, instr: il.set_reg(4, 'a', il.reg(4, 'x'))
}


def init_misc_ops():
    for misc_op in [BPF_TAX, BPF_TXA]:
        name = BPF_MISC_LOOKUP[misc_op]
        full_opcode = BPF_MISC | misc_op
        InstructionNames[full_opcode] = name
        InstructionFormatters[full_opcode] = empty_formatter
        InstructionLLIL[full_opcode] = BPF_MISC_LLIL[misc_op]


init_misc_ops()


class BPFInstruction:
    def __init__(self, instruction, addr=0, little_endian=True):
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


# noinspection PyBroadException
def get_instruction(data, addr):
    try:
        instr = BPFInstruction(data, addr)
        return True, instr
    except:
        pass
    return False, None


# noinspection PyAbstractClass,PyAbstractClass
class BPFArch(Architecture):
    name = "BPF"
    address_size = 4
    default_int_size = 4
    max_instr_length = 8
    regs = {
        "a": RegisterInfo("a", 4),  # accumulator
        "x": RegisterInfo("x", 4),  # index
        # BPF only has 16 Memory address to store to
        # and binary ninja doesn't have a concept of different
        # address spaces, so hacked BPF memory into registers
        "m0": RegisterInfo("m0", 4),  # M[0]
        "m1": RegisterInfo("m1", 4),  # M[1]
        "m2": RegisterInfo("m2", 4),  # M[2]
        "m3": RegisterInfo("m3", 4),  # M[3]
        "m4": RegisterInfo("m4", 4),  # M[4]
        "m5": RegisterInfo("m5", 4),  # M[5]
        "m6": RegisterInfo("m6", 4),  # M[6]
        "m7": RegisterInfo("m7", 4),  # M[7]
        "m8": RegisterInfo("m8", 4),  # M[8]
        "m9": RegisterInfo("m9", 4),  # M[9]
        "m10": RegisterInfo("m10", 4),  # M[10]
        "m11": RegisterInfo("m11", 4),  # M[11]
        "m12": RegisterInfo("m12", 4),  # M[12]
        "m13": RegisterInfo("m13", 4),  # M[13]
        "m14": RegisterInfo("m14", 4),  # M[14]
        "m15": RegisterInfo("m15", 4),  # M[15]
        # binary ninja doesn't have a concept of differnt
        # address space, so all packet accesses go through a
        # virtual pkt pointer
        "pkt": RegisterInfo("pkt", 4),
        # virtual address to hold size of packet
        "len": RegisterInfo("len", 4),
        # binary ninja needs a stack or is unhappy
        "dummystack": RegisterInfo("dummystack", 4),
        # virtual register to make clear what return value is in llil
        "dummyret": RegisterInfo("dummyret", 4),
        # virtual link register to return to. BPF return is more akin to a halt
        "dummylr": RegisterInfo("dummylr", 4),

    }
    # because I _must_ have a stack pointer. (BPF has no stack)
    stack_pointer = "dummystack"

    def perform_get_instruction_info(self, data, addr):
        valid, instr = get_instruction(data, addr)
        result = InstructionInfo()
        if valid:
            result.length = 8
            if instr.opcode in InstructionInfoModders:
                InstructionInfoModders[instr.opcode](result, instr)
            return result
        else:
            # This is _EXCEEDINGLY_ important to return on failure.
            # Things will break in creative ways if anything other than None
            # is returned for invalid data
            return None

    def perform_get_instruction_text(self, data, addr):
        valid, instr = get_instruction(data, addr)
        if not valid:
            # This is _EXCEEDINGLY_ important to return on failure.
            # Things will break in creative ways if anything other than None
            # is returned for invalid data
            return None
        if instr.opcode not in InstructionNames:
            print 'debug: %s' % instr
            return (
                [InstructionTextToken(InstructionTextTokenType.InstructionToken, "unk opcode 0x%x" % instr.opcode)], 8)
        tokens = []
        instr_name = InstructionNames[instr.opcode]
        tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, instr_name))
        formatter = InstructionFormatters[instr.opcode]
        extra_tokens = formatter(instr)
        if len(extra_tokens) > 0:
            tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, " ")] + extra_tokens
        return tokens, 8

    def perform_get_instruction_low_level_il(self, data, addr, il):
        print 'Asking to decode %d bytes at 0x%x' % (len(data), addr)
        valid, instr = get_instruction(data[0:8], addr)
        if not valid:
            print '*********** Tried an failed **********'
            # This is _EXCEEDINGLY_ important to return on failure.
            # Things will break in creative ways if anything other than None
            # is returned for invalid data
            return None
        if instr.opcode not in InstructionLLIL:
            print 'Adding il.undefined()'
            # il.append(il.unimplemented())
            il.append(il.undefined())
        else:
            il_exp = InstructionLLIL[instr.opcode](il, instr)
            if il_exp is not None:
                il.append(il_exp)
                print 'appended: %s' % LowLevelILInstruction(il, il_exp.index)
            else:
                print 'Failed to generate il'

        print 'Full IL Decode was successful len(il): %d' % len(il)
        return 8


def view2str(bv):
    """
    Buffers all data from a binary view to a string
    :param bv: BinaryView to read from
    :return: string of the data underlying bv
    """
    size = len(bv)
    txt = bv.read(0, size)
    return txt


def construct_bpf_prog(txt):
    """
    Constructs a BPF program from a line of text with the following format
    This is the same format the xt_bpf iptables extension takes as well as the one
    cloudflare's bpftools program outputs
    <num instructions>,<opcode jt jf k>,[opcode jt jf k,]
    :param txt: line to parse
    :return: binary representation of the line on success
             None on failure
    """
    top_tokens = txt.rstrip().split(',')
    try:
        if len(top_tokens) <= 1:
            return False
        num_tokens = int(top_tokens[0])
        result = ''
        result += struct.pack('I', num_tokens)
        for top_token in top_tokens[1:]:
            if top_token == '':
                continue
            instr_tokens = top_token.split(' ')
            opcode = int(instr_tokens[0])
            jt = int(instr_tokens[1])
            jf = int(instr_tokens[2])
            k = int(instr_tokens[3])
            result += struct.pack('HBBI', opcode, jt, jf, k)
        return result
    except:
        pass
    return None


# noinspection PyAbstractClass,PyAbstractClass
class XTBPFView(BinaryView):
    name = "XTBPF"
    long_name = "xt_bpf Prog"

    @classmethod
    def is_valid_for_data(cls, data):
        return construct_bpf_prog(view2str(data)) is not None

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.platform = Architecture['BPF'].standalone_platform
        virtualdata = construct_bpf_prog(view2str(data))
        num_instr, = struct.unpack('I', virtualdata[0:4])
        size = num_instr * 8
        self.virtualcode = virtualdata[4:]

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return 0

    def init(self):
        self.add_entry_point(0)

    def perform_get_length(self):
        return len(self.virtualcode)

    def perform_read(self, addr, length):
        result = self.virtualcode[addr: addr + length]
        return result


# noinspection PyAbstractClass
class BPFView(BinaryView):
    name = "BPF"
    long_name = "BPF"

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.platform = Architecture['BPF'].standalone_platform
        num_instr, = struct.unpack('I', self.parent_view.read(0, 4))
        size = num_instr * 8
        self.add_auto_segment(0, size, 4, size,
                              SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable | SegmentFlag.SegmentExecutable)

    # noinspection PyUnusedLocal
    @classmethod
    def is_valid_for_data(cls, data):
        return True

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return 0

    def init(self):
        self.add_entry_point(0)


for full_opcode in InstructionNames:
    print '0x%x : %s' % (full_opcode, InstructionNames[full_opcode])
XTBPFView.register()
BPFArch.register()
BPFView.register()
