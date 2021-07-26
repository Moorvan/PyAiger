import ctypes as c
from collections import OrderedDict

import z3
from z3 import *


class aiger_and(c.Structure):
    _fields_ = [
        ('lhs', c.c_uint),
        ('rhs0', c.c_uint),
        ('rhs1', c.c_uint)
    ]


class aiger_symbol(c.Structure):
    _fields_ = [
        ('lit', c.c_uint),
        ('next', c.c_uint),
        ('reset', c.c_uint),
        ('size', c.c_uint),
        ('lits', c.POINTER(c.c_uint)),
        ('name', c.c_char_p)
    ]


class aiger(c.Structure):
    _fields_ = [
        ('maxvar', c.c_uint),
        ('num_inputs', c.c_uint),
        ('num_latches', c.c_uint),
        ('num_outputs', c.c_uint),
        ('num_ands', c.c_uint),
        ('num_bad', c.c_uint),
        ('num_constraints', c.c_uint),
        ('num_justice', c.c_uint),
        ('num_fairness', c.c_uint),

        ('inputs', c.POINTER(aiger_symbol)),
        ('latches', c.POINTER(aiger_symbol)),
        ('outputs', c.POINTER(aiger_symbol)),
        ('bad', c.POINTER(aiger_symbol)),
        ('constrains', c.POINTER(aiger_symbol)),
        ('justice', c.POINTER(aiger_symbol)),
        ('fairness', c.POINTER(aiger_symbol)),
        ('ands', c.POINTER(aiger_and)),
        ('comments', c.POINTER(c.c_char_p))
    ]


class aig_model:
    def __init__(self, src):
        self._setup_lib()
        aig = self.aiger_init()
        error = self.aiger_read(aig, c.c_char_p(bytes(str.encode(src))))
        if error is not None:
            raise ValueError(bytes.decode(error))
        self.max_var = aig.contents.maxvar
        self.num_inputs = aig.contents.num_inputs
        self.num_latches = aig.contents.num_latches
        self.num_outputs = aig.contents.num_outputs
        self.num_ands = aig.contents.num_ands
        self.num_bad = aig.contents.num_bad
        self.num_constraints = aig.contents.num_constraints

        self.inputs = aig.contents.inputs
        self.latches = aig.contents.latches
        self.outputs = aig.contents.outputs
        self.bad = aig.contents.bad
        self.constrains = aig.contents.constrains
        self.ands = aig.contents.ands

    def _setup_lib(self):
        self.libc = c.cdll.LoadLibrary('./libaiger.so')
        l = self.libc

        self.aiger_init = l.aiger_init
        self.aiger_init.restype = c.POINTER(aiger)
        self.aiger_init.argtypes = []

        self.aiger_read = l.aiger_open_and_read_from_file
        self.aiger_read.restype = c.c_char_p
        self.aiger_read.argtypes = [c.POINTER(aiger), c.c_char_p]

    def parse(self):
        p_index = self.max_var
        k_index = self.max_var * 2

        inp = OrderedDict()
        inp_z3 = OrderedDict()
        for it in range(self.num_inputs):
            i = self.inputs[it]
            inp[int(i.lit / 2)] = bytes.decode(i.name or b'')
            inp_z3[int(i.lit / 2)] = Bool(str(int(i.lit / 2)))

        vars = OrderedDict()
        vars_p = OrderedDict()
        vars_z3 = OrderedDict()
        vars_p_z3 = OrderedDict()
        for it in range(self.num_latches):
            i = self.latches[it]
            vars[int(i.lit / 2)] = bytes.decode(i.name or b'')
            vars_p[p_index + int(i.lit / 2)] = bytes.decode(i.name or b'') + '\''
            vars_z3[int(i.lit / 2)] = Bool(str(int(i.lit / 2)))
            vars_p_z3[p_index + int(i.lit / 2)] = Bool(str(int(p_index + int(i.lit / 2))))

        ands_z3 = OrderedDict()
        for it in range(self.num_ands):
            i = self.ands[it]
            if i.rhs0 == 1:
                rhs0 = True
            elif i.rhs0 == 0:
                rhs0 = False
            elif i.rhs0 & 1 == 1:
                v = int(i.rhs0 / 2)
                if v in inp_z3.keys():
                    rhs0 = Not(inp_z3[v])
                elif v in vars_z3.keys():
                    rhs0 = Not(vars_z3[v])
                elif v in ands_z3.keys():
                    rhs0 = Not(ands_z3[v])
                else:
                    raise ValueError("Error in AND definition, in node " + v)
            else:
                v = int(i.rhs0 / 2)
                if v in inp_z3.keys():
                    rhs0 = inp_z3[v]
                elif v in vars_z3.keys():
                    rhs0 = vars_z3[v]
                elif v in ands_z3.keys():
                    rhs0 = ands_z3[v]
                else:
                    raise ValueError("Error in AND definition, in node " + v)

            if i.rhs1 == 1:
                rhs1 = True
            elif i.rhs1 == 0:
                rhs1 = False
            elif i.rhs1 & 1 == 1:
                v = int(i.rhs1 / 2)
                if v in inp_z3.keys():
                    rhs1 = Not(inp_z3[v])
                elif v in vars_z3.keys():
                    rhs1 = Not(vars_z3[v])
                elif v in ands_z3.keys():
                    rhs1 = Not(ands_z3[v])
                else:
                    raise ValueError("Error in AND definition, in node " + v)
            else:
                v = int(i.rhs1 / 2)
                if v in inp_z3.keys():
                    rhs1 = inp_z3[v]
                elif v in vars_z3.keys():
                    rhs1 = vars_z3[v]
                elif v in ands_z3.keys():
                    rhs1 = ands_z3[v]
                else:
                    raise ValueError("Error in AND definition, in node " + v)

            ands_z3[i.lhs / 2] = And(rhs0, rhs1)

        inits_z3 = list()
        for it in range(self.num_latches):
            i = self.latches[it]
            if i.reset == 0:
                inits_z3.append(Not(vars_z3[int(i.lit / 2)]))
            elif i.reset == 1:
                inits_z3.append(vars_z3[int(i.lit / 2)])

        trans_z3 = list()
        for it in range(self.num_latches):
            i = self.latches[it]
            if i.next == 0:
                trans_z3.append(Not(vars_p_z3[p_index + int(i.lit / 2)]))
            elif i.next == 1:
                trans_z3.append(vars_p_z3[p_index + int(i.lit / 2)])
            elif i.next & 1 == 0:
                v = int(i.next / 2)
                if v in inp_z3.keys():
                    trans_z3.append(vars_p_z3[p_index + int(i.lit / 2)] == inp_z3[v])
                elif v in vars_z3.keys():
                    trans_z3.append(vars_p_z3[p_index + int(i.lit / 2)] == vars_z3[v])
                elif v in ands_z3.keys():
                    trans_z3.append(vars_p_z3[p_index + int(i.lit / 2)] == ands_z3[v])
                else:
                    raise ValueError("Error in transition relation, in latch " + it)
            else:
                v = int(i.next / 2)
                if v in inp_z3.keys():
                    trans_z3.append(vars_p_z3[p_index + int(i.lit / 2)] == Not(inp_z3[v]))
                elif v in vars_z3.keys():
                    trans_z3.append(vars_p_z3[p_index + int(i.lit / 2)] == Not(vars_z3[v]))
                elif v in ands_z3.keys():
                    trans_z3.append(vars_p_z3[p_index + int(i.lit / 2)] == Not(ands_z3[v]))
                else:
                    raise ValueError("Error in transition relation, in latch " + it)

        bad_z3 = list()
        if self.num_outputs > 0:
            print("Consider the output(s) as bad property.")
            for it in range(self.num_outputs):
                i = self.outputs[it]
                if i.lit & 1 == 0:
                    v = int(i.lit / 2)
                    if v in inp_z3.keys():
                        bad_z3.append(Not(inp_z3[v]))
                    elif v in vars_z3.keys():
                        bad_z3.append(Not(vars_z3[v]))
                    elif v in ands_z3.keys():
                        bad_z3.append(Not(ands_z3[v]))
                    else:
                        raise ValueError("Error in property(output) definition " + it)
                else:
                    v = int(i.lit / 2)
                    if v in inp_z3.keys():
                        bad_z3.append(inp_z3[v])
                    elif v in vars_z3.keys():
                        bad_z3.append(vars_z3[v])
                    elif v in ands_z3.keys():
                        bad_z3.append(ands_z3[v])
                    else:
                        raise ValueError("Error in property(output) definition " + it)

        for it in range(self.num_bad):
            i = self.bad[it]
            if i.lit & 1 == 0:
                v = int(i.lit / 2)
                if v in inp_z3.keys():
                    bad_z3.append(Not(inp_z3[v]))
                elif v in vars_z3.keys():
                    bad_z3.append(Not(vars_z3[v]))
                elif v in ands_z3.keys():
                    bad_z3.append(Not(ands_z3[v]))
                else:
                    raise ValueError("Error in property definition " + it)
            else:
                v = int(i.lit / 2)
                if v in inp_z3.keys():
                    bad_z3.append(inp_z3[v])
                elif v in vars_z3.keys():
                    bad_z3.append(vars_z3[v])
                elif v in ands_z3.keys():
                    bad_z3.append(ands_z3[v])
                else:
                    raise ValueError("Error in property definition " + it)

        return inp_z3, vars_z3, vars_p, inits_z3, trans_z3, bad_z3


if __name__ == '__main__':
    aig = aig_model('mutual_noproc.aig')
    print(aig.parse())
