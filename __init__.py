import struct
import socket

from binaryninja.architecture import Architecture
from binaryninja.binaryview import BinaryView
from binaryninja.enums import (BranchType, InstructionTextTokenType,
                               SegmentFlag)
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.lowlevelil import LowLevelILInstruction
from binaryninja.plugin import PluginCommand
from bpfconstants import *
from bpfllil import *

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

def empty_formatter(instr):
    return []

ld_source_formatters = {
    BPF_ABS: lambda instr: [TextToken('['), IntegerToken(instr.k), TextToken(']')],
    BPF_IND: lambda instr: [TextToken('['), IntegerToken(instr.k), TextToken(' + '), RegisterToken('x'),
                            TextToken(']')],
    BPF_MEM: lambda instr: [TextToken('M['), IntegerToken(instr.k), TextToken(']')],
    BPF_IMM: lambda instr: [IntegerToken(instr.k)],
    BPF_LEN: lambda instr: [RegisterToken('len')],
    BPF_MSH: lambda instr: [TextToken('4*(['), IntegerToken(instr.k), TextToken(']&0xf)')]
}
aluret_src_formatters = {
    BPF_K: lambda instr: [IntegerToken(instr.k)],
    BPF_A: lambda instr: [RegisterToken('a')],
    BPF_X: lambda instr: [RegisterToken('x')],
}


dest_tuples = {
    BPF_LD: (4, 'a'),
    BPF_LDX: (4, 'x'),
    BPF_LD | BPF_H: (2, 'a'),
    BPF_LD | BPF_B: (1, 'a'),
    BPF_LDX | BPF_H: (2, 'x'),
    BPF_LDX | BPF_B: (1, 'x'),
}

def ja_modder(iinfo, instr):
    """
    Mods instruction info for jump always instruction
    :param iinfo: InstructionInfo to modify
    :param instr: instruction to modify iinfo with
    :return: None
    """
    iinfo.add_branch(BranchType.BranchAlways, instr.ja_target)


def jc_modder(iinfo, instr):
    """
    Mods instruction info for a conditional jump
    :param iinfo: InstructionInfo to modify
    :param instr: instruction to modify iinfo with
    :return: None
    """
    iinfo.add_branch(BranchType.TrueBranch, instr.jt_target)
    iinfo.add_branch(BranchType.FalseBranch, instr.jf_target)


def ja_formatter(instr):
    """
    Returns extra disassembly tokens for a jump always
    :param instr: instruction to get tokens from
    :return: list of tokens with jump target
    """
    return [AddressToken(instr.ja_target)]


def jc_formatter(instr):
    """
    Returns extra disassembly tokens for conitional jump
    :param instr: instruction to get tokens from
    :return: list of tokens with comparison target and jump targets
    """
    return [IntegerToken(instr.k), SeperatorToken(),
            AddressToken(instr.jt_target), SeperatorToken(),
            AddressToken(instr.jf_target)]

def ret_modder(iinfo, instr):
    """
    Mods instruction info for ret
    :param iinfo: InstructionInfo to modify
    :param instr: instruction to add return info for
    :return: None
    """
    iinfo.add_branch(BranchType.FunctionReturn)


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
            InstructionFormatters[full_opcode] = ld_source_formatters[op_mode]


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


def init_alu_ops():
    """
    Wire up the alu ops
    :return: None
    """
    for alu_op in BPF_ALU_LOOKUP:
        name = BPF_ALU_LOOKUP[alu_op]
        for src in [BPF_K, BPF_X]:
            full_opcode = BPF_ALU | alu_op | src
            InstructionNames[full_opcode] = name
            InstructionFormatters[full_opcode] = aluret_src_formatters[src]
            InstructionLLIL[full_opcode] = ALU_LLIL[alu_op](aluret_src_IL[src])


def init_ret_ops():
    """
    Wire up the ret ops
    :return: None
    """
    for ret_src in [BPF_K, BPF_X, BPF_A]:
        full_opcode = BPF_RET | ret_src
        InstructionNames[full_opcode] = 'ret'
        if DO_RET_IL:
            InstructionLLIL[full_opcode] = get_ret_llil(ret_src)
        InstructionFormatters[full_opcode] = aluret_src_formatters[ret_src]
        InstructionInfoModders[full_opcode] = ret_modder


def init_jmp_ops():
    """
    Wire up the jmp ops
    :return: None
    """
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

def init_misc_ops():
    """
    Wire up the misc ops
    :return: None
    """
    for misc_op in [BPF_TAX, BPF_TXA]:
        name = BPF_MISC_LOOKUP[misc_op]
        full_opcode = BPF_MISC | misc_op
        InstructionNames[full_opcode] = name
        InstructionFormatters[full_opcode] = empty_formatter
        InstructionLLIL[full_opcode] = BPF_MISC_LLIL[misc_op]

class BPFInstruction:
    """
    Easy was of representing and manipulating bpf Instruction
    """
    def __init__(self, instruction, addr=0, little_endian=True):
        """
        Unpacks instruction and initializes class
        :param instruction: 8 bytes to unpack
        :param addr: address of this instruction in virtual address space
        :param little_endian: are these bytes little endian?
        """
        unpack_endian = '<'
        if not little_endian:
            unpack_endian = '>'
        unpack_str = unpack_endian + 'HBBI'
        self.opcode, self.jt, self.jf, self.k = \
            struct.unpack(unpack_str, instruction)
        self.addr = addr

    def offset2addr(self, offset):
        """
        All jumps are a positive displacement from an the pc
        This converts an offset into an address
        :param offset: offset from pc to get address for
        :return: address of pc + offset
        """
        return self.addr + 8 * (offset + 1)

    @property
    def jt_target(self):
        """
        gets absolute address of jt offset
        :return: absolute address of jt offset
        """
        return self.offset2addr(self.jt)

    @property
    def jf_target(self):
        """
        gets absolute address of jf offset
        :return: absolute address of jf offset
        """
        return self.offset2addr(self.jf)

    @property
    def ja_target(self):
        """
        gets absolute address of ja offset
        :return: absolute address of ja offset
        """
        return self.offset2addr(self.k)

def get_instruction(data, addr):
    """
    Used to check if an instruction parses
    :param data: data to parse
    :param addr: address of instruction
    :return: tuple of (success, result)
    where success is True/False and
    result is either a BPFInstruction, or None
    """
    try:
        instr = BPFInstruction(data, addr)
        return True, instr
    except:
        pass
    return False, None


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
        # virtual pkt register that notionally holds the address of packet start
        # at program entry
        "pkt": RegisterInfo("pkt", 4),
        # virtual address to notionally holds
        # size of packet at program entry
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
            log('debug: %s' % instr)
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
        log('Asking to decode %d bytes at 0x%x' % (len(data), addr))
        valid, instr = get_instruction(data[0:8], addr)
        if not valid:
            log('*********** Tried an failed **********')
            # This is _EXCEEDINGLY_ important to return on failure.
            # Things will break in creative ways if anything other than None
            # is returned for invalid data
            return None
        if instr.opcode not in InstructionLLIL:
            log('Adding il.undefined()')
            # il.append(il.unimplemented())
            il.append(il.undefined())
        else:
            il_exp = InstructionLLIL[instr.opcode](il, instr)
            if il_exp is not None:
                il.append(il_exp)
                log('appended: %s' % LowLevelILInstruction(il, il_exp.index))
            else:
                log('Failed to generate il')

        log('Full IL Decode was successful len(il): %d' % len(il))
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


class XTBPFView(BinaryView):
    """
    Used for strings of the kind bpftools output
    """
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

class BPFView(BinaryView):
    """
    Used for an already binary packed representation
    """
    name = "BPF"
    long_name = "BPF"

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.platform = Architecture['BPF'].standalone_platform
        num_instr, = struct.unpack('I', self.parent_view.read(0, 4))
        size = num_instr * 8
        self.add_auto_segment(0, size, 4, size,
                              SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable | SegmentFlag.SegmentExecutable)

    @classmethod
    def is_valid_for_data(cls, data):
        return True

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return 0

    def init(self):
        self.add_entry_point(0)

def hton(txt):
    return txt[3] + txt[2] + txt[1] + txt[0]
def get_ip_at(bv, addr):
    k_raw = hton(bv.read(addr + 4, 4))
    result = socket.inet_ntoa(k_raw)
    return result

def annotate_ip_at(bv, addr):
    funct = function = bv.get_basic_blocks_at(addr)[0].function
    ip = get_ip_at(bv, addr)
    funct.set_comment(addr, ip)
    log('Commenting 0x%x with %s')

def init_module():
    init_load_ops()
    init_store_ops()
    init_alu_ops()
    init_jmp_ops()
    init_ret_ops()
    init_misc_ops()
    for full_opcode in InstructionNames:
        log('0x%x : %s' % (full_opcode, InstructionNames[full_opcode]))
    XTBPFView.register()
    BPFArch.register()
    BPFView.register()
    PluginCommand.register_for_address('BPF Annotate IP', 'Converts BPF K value to IP', annotate_ip_at)

init_module()