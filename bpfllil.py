from binaryninja.architecture import Architecture
from bpfconstants import *


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
    return il.reg(4, 'm%d' % addr)


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


aluret_src_IL = {
    BPF_K: lambda il, instr: il.const(4, instr.k),
    BPF_A: lambda il, instr: il.reg(4, 'a'),
    BPF_X: lambda il, instr: il.reg(4, 'x')
}


def valid_label(il, target):
    """
    Returns a garunteed valid llil label for an address
    :param il: llil function to generate label with
    :param target: address to generate label for
    :return: valid llil label for target
    """
    label = il.get_label_for_address(Architecture['BPF'], target)
    if label is not None:
        log('label for 0x%x existed' % target)
        return label
    log('Adding label for 0x%x and trying again' % target)
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
    """
    Returns llil to conditionally branch
    :param il: llil function to generate expression with
    :param instr: instruction to generate expression from
    :param cond: conditional expression
    :return: llil expression for conditional jump
    """
    t = valid_label(il, instr.jt_target)
    f = valid_label(il, instr.jf_target)
    log('jt(0x%x) Label Handle: %s' % (instr.jt_target, t.handle))
    log('jf(0x%x) Label Handle: %s' % (instr.jf_target, f.handle))
    return il.if_expr(cond, t, f)


def get_add_llil(src):
    """
    Returns llil to add
    :param src: source of operation
    :return: generator for llil expression for add
    """

    def add_llil(il, instr):
        return il.set_reg(4, 'a', il.add(4, il.reg(4, 'a'), src(il, instr)))

    return add_llil


def get_sub_llil(src):
    """
    Returns llil to sub
    :param src: source of operation
    :return: generator for llil expression for sub
    """

    def sub_llil(il, instr):
        return il.set_reg(4, 'a', il.sub(4, il.reg(4, 'a'), src(il, instr)))

    return sub_llil


def get_mul_llil(src):
    """
    Returns llil to mul
    :param src: source of operation
    :return: generator for llil expression for mul
    """

    def mul_llil(il, instr):
        return il.set_reg(4, 'a', il.mult(4, il.reg(4, 'a'), src(il, instr)))

    return mul_llil


def get_div_llil(src):
    """
    Returns llil to div
    :param src: source of operation
    :return: generator for llil expression for add
    """

    def div_llil(il, instr):
        return il.set_reg(4, 'a', il.div_unsigned(4, il.reg(4, 'a'), src(il, instr)))

    return div_llil


def get_neg_llil(src):
    """
    Returns llil to bitwise not
    :param src: ignored
    :return: generator for llil expression for not
    """

    def neg_llil(il, instr):
        return il.set_reg(4, 'a', il.not_expr(4, il.reg(4, 'a')))

    return neg_llil


def get_and_llil(src):
    """
    Returns llil to and
    :param src: source of operation
    :return: generator for llil expression for and
    """

    def and_llil(il, instr):
        return il.set_reg(4, 'a', il.and_expr(4, il.reg(4, 'a'), src(il, instr)))

    return and_llil


def get_or_llil(src):
    """
    Returns llil to or
    :param src: source of operation
    :return: generator for llil expression for or
    """

    def or_llil(il, instr):
        return il.set_reg(4, 'a', il.or_exp(4, il.reg(4, 'a'), src(il, instr)))

    return or_llil


def get_lsh_llil(src):
    """
    Returns llil to left shift
    :param src: source of operation
    :return: generator for llil expression for lsh
    """

    def lsh_llil(il, instr):
        return il.set_reg(4, 'a', il.shift_left(4, il.reg(4, 'a'), src(il, instr)))

    return lsh_llil


def get_rsh_llil(src):
    """
    Returns llil to mod
    :param src: source of operation
    :return: generator for llil expression for mod
    """

    def rsh_llil(il, instr):
        return il.set_reg(4, 'a', il.logical_shift_right(4, il.reg(4, 'a'), src(il, instr)))

    return rsh_llil


def get_mod_llil(src):
    """
    Returns llil to mod
    :param src: source of operation
    :return: generator for llil expression for mod
    """

    def mod_llil(il, instr):
        return il.set_reg(4, 'a', il.mod(4, il.reg(4, 'a'), src(il, instr)))

    return mod_llil


def get_xor_llil(src):
    """
    Returns llil to xor
    :param src: source of operation
    :return: generator for llil expression for xor
    """

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


def get_ret_llil(src):
    """
    returns llil for ret
    :param src: source of ret value
    :return: llil for ret with src
    """

    def ret_llil(il, instr):
        if src == BPF_X:
            src_il = il.reg(4, 'x')
        if src == BPF_K:
            src_il = il.const(4, instr.k)
        ret_value_exp = il.set_reg(4, 'dummyret', src_il)
        il.append(ret_value_exp)
        return il.ret(il.reg(4, 'dummylr'))

    return ret_llil


def get_je_llil(src):
    """
    gets llil generator for jump equal conditional jump
    :param src: source for comparison BPF_K or BPF_X
    :return: function to generate llil for je
    """

    def je_llil(il, inst):
        src_il = aluret_src_IL[src](il, inst)
        cond = il.compare_equal(4, il.reg(4, 'a'), src_il)
        return jc_il(il, inst, cond)

    return je_llil


def get_jgt_llil(src):
    """
    gets llil generator for jump greater than conditional jump
    :param src: source for comparison BPF_K or BPF_X
    :return: function to generate llil for jgt
    """

    def jgt_llil(il, inst):
        src_il = aluret_src_IL[src](il, inst)
        cond = il.compare_unsigned_greater_than(4, il.reg(4, 'a'), src_il)
        return jc_il(il, inst, cond)

    return jgt_llil


def get_jge_llil(src):
    """
    gets llil generator for jump greater or equal conditional jump
    :param src: source for comparison BPF_K or BPF_X
    :return: function to generate llil for jge
    """

    def jge_llil(il, inst):
        src_il = aluret_src_IL[src](il, inst)
        cond = il.compare_unsigned_greater_equal(4, il.reg(4, 'a'), src_il)
        return jc_il(il, inst, cond)

    return jge_llil


def get_jset_llil(src):
    """
    gets llil generator for jset conditional jump
    jump if (a & src)
    :param src: source for comparison BPF_K or BPF_X
    :return: function to generate llil for jset
    """

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
BPF_MISC_LLIL = {
    BPF_TAX: lambda il, instr: il.set_reg(4, 'x', il.reg(4, 'a')),
    BPF_TXA: lambda il, instr: il.set_reg(4, 'a', il.reg(4, 'x'))
}
