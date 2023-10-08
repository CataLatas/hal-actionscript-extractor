#!/usr/bin/python3

# Some of the code you'll see here is bad, but it works.

import argparse
import os
import string
import sys

LABEL_CHARSET = string.ascii_letters + string.digits + '_'  # Valid characters for labels

LAST_SCRIPT = 28  # Amount of scripts

DATA_TYPE_SIZES = {
    'label_16': 2,  # 16-bit address (prefferably a label, when available)
    'label_24': 3,  # 24-bit address (prefferably a label, when available)
    'imm_8':    1,  # 8-bit immediate (hex representation)
    'imm_s8':   1,  # 8-bit signed immediate (decimal representation)
    'imm_u8':   1,  # 8-bit unsigned immediate (decimal representation)
    'imm_16':   2,  # 16-bit immediate (hex representation)
    'imm_s16':  2,  # 16-bit signed immediate (decimal representation)
    'imm_u16':  2,  # 16-bit unsigned immediate (decimal representation)
    'addr_16':  2,  # 16-bit address
    'addr_24':  3,  # 24-bit address
    'addr_32':  4,  # 32-bit address (high byte ignored)
    'obj_var':  1,  # Object variable (i.e. VAR0, VAR1, ..., VAR7)
    'reg':      0,  # The work register
    'nop':      0,  # Special, used only by opcode 0x0F (ONTICK NOP)
}

# (mnemonic, data types separated by spaces)
OPCODES = (
    ('END',         ''),                       # 00
    ('HALT',        ''),                       # 01
    ('WAIT',        'imm_u8'),                 # 02
    ('ONTICK',      'addr_24'),                # 03
    ('ENDTICK',     ''),                       # 04
    ('LOOP',        'imm_8'),                  # 05
    ('LOOP',        'reg'),                    # 06
    ('ENDLOOP',     ''),                       # 07
    ('JSL',         'label_24'),               # 08
    ('RTL',         ''),                       # 09
    ('JSR',         'label_16'),               # 0A
    ('MULTIJSR',    'imm_u8'),                 # 0B
    ('RTS',         ''),                       # 0C
    ('JML',         'label_24'),               # 0D
    ('JMP',         'label_16'),               # 0E
    ('MULTIJMP',    'imm_u8'),                 # 0F
    ('JEQ',         'label_16'),               # 10
    ('JNE',         'label_16'),               # 11
    ('BREAKEQ',     'label_16'),               # 12
    ('BREAKNE',     'label_16'),               # 13
    ('SPRITEMAP',   'addr_24'),                # 14
    ('ONDRAW',      'addr_16'),                # 15
    ('UNK16',       'addr_16'),                # 16 - TODO: ONMOVE?
    ('MOV',         'reg imm_16'),             # 17
    ('MOV',         'reg addr_16'),            # 18
    ('MOV',         'obj_var addr_16'),        # 19
    ('MOV.b',       'addr_16 imm_8'),          # 1A
    ('MOV.w',       'addr_16 imm_16'),         # 1B
    ('BINOP',       'obj_var imm_u8 imm_16'),  # 1C
    ('BINOP.b',     'addr_16 imm_u8 imm_8'),   # 1D
    ('BINOP.w',     'addr_16 imm_u8 imm_16'),  # 1E
    ('BINOP',       'reg imm_u8 imm_16'),      # 1F
    ('MOV',         'obj_var reg'),            # 20
    ('MOV',         'reg obj_var'),            # 21
    ('WAIT',        'obj_var'),                # 22
    ('SETPOSE',     'obj_var'),                # 23
    ('UNK24',       ''),                       # 24 - TODO: ZERO $6B6E, $6BE8, $6C62, $6CDC
    ('UNK25',       ''),                       # 25 - TODO: ZERO $6C62, $6CDC
    ('SETXPOS',     'imm_16'),                 # 26
    ('SETYPOS',     'imm_16'),                 # 27
    ('ADDXPOS',     'imm_16'),                 # 28
    ('ADDYPOS',     'imm_16'),                 # 29
    ('UNK2A',       'imm_8 imm_16'),           # 2A
    ('UNK2B',       'imm_8 imm_16'),           # 2B
    ('UNK2C',       'imm_8 imm_16'),           # 2C
    ('UNK2D',       'imm_8 imm_16'),           # 2D
    ('UNK2E',       'imm_8'),                  # 2E
    ('UNK2F',       'imm_8 imm_16'),           # 2F
    ('UNK30',       'imm_8 imm_16'),           # 30
    ('UNK31',       'imm_8 imm_16'),           # 31
    ('UNK32',       'imm_8 imm_16'),           # 32
    ('UNK33',       'imm_16'),                 # 33 - TODO: SET $64B6
    ('UNK34',       'imm_8'),                  # 34 - TODO: CALL $00921B
    ('SETPOSE.w',   'imm_16'),                 # 35
)

OPCODES_WAITED = (
    ('SETPOSE.b',   'imm_s8'),                 # 4x
    ('ADDPOSE',     'imm_s8'),                 # 5X
    ('INCPOSE',     ''),                       # 6x
    ('DECPOSE',     ''),                       # 7x
    ('UNK8x',       'imm_16'),                 # 8X - TODO: SET $6B6E
    ('UNK9x',       'imm_16'),                 # 9X - TODO: SET $6BE8
    ('UNKAx',       'imm_16'),                 # AX - TODO: SET $6C62
    ('UNKBx',       'imm_16'),                 # BX - TODO: SET $6CDC
    ('ASMCALL',     'addr_24'),                # Cx
    ('PRESETCALL',  'imm_8'),                  # Dx
    ('UNKEx',       'imm_8'),                  # Ex - TODO: CALL $00D12D / SOUND SOMETHING
    ('UNKFx',       'imm_8'),                  # Fx - TODO: CALL $00D003 / SOUND SOMETHING
)

# Kirby Super Star introduced an alternate, mysterious interpreter!
# Opcodes are 00, 02, 04, 06, ...
# But if the lsb of an opcode is set, the next byte acts as "WAIT #x"
# TODO: When are these used????????????????
OPCODES_ALT = (
    OPCODES[0x00],                              # 00
    OPCODES[0x01],                              # 02
    OPCODES[0x02],                              # 04
    OPCODES[0x05],                              # 06
    OPCODES[0x06],                              # 08
    OPCODES[0x07],                              # 0A
    OPCODES[0x0B],                              # 0C
    OPCODES[0x0C],                              # 0E
    OPCODES[0x0E],                              # 10
    OPCODES[0x0F],                              # 12
    OPCODES[0x10],                              # 14
    OPCODES[0x11],                              # 16
    OPCODES[0x14],                              # 18
    OPCODES[0x15],                              # 1A
    OPCODES[0x16],                              # 1C
    OPCODES[0x17],                              # 1E
    OPCODES[0x18],                              # 20
    OPCODES[0x19],                              # 22
    OPCODES[0x1A],                              # 24
    OPCODES[0x1B],                              # 26
    ('MOVINDEXED.w', 'addr_16 imm_16'),         # 28 addr_16[this.index] = imm_16
    ('MOVINDEXED.w', 'reg addr_16'),            # 2A reg = addr_16[this.index]
    OPCODES[0x20],                              # 2C
    OPCODES[0x21],                              # 2E
    OPCODES[0x33],                              # 30
    OPCODES[0x34],                              # 32
    OPCODES[0x24],                              # 34
    OPCODES_WAITED[0x08-0x04],                  # 36
    OPCODES_WAITED[0x09-0x04],                  # 38
    OPCODES_WAITED[0x0A-0x04],                  # 3A
    OPCODES_WAITED[0x0B-0x04],                  # 3C
    OPCODES_WAITED[0x04-0x04],                  # 3E
    OPCODES_WAITED[0x05-0x04],                  # 40
    OPCODES_WAITED[0x06-0x04],                  # 42
    OPCODES_WAITED[0x07-0x04],                  # 44
    OPCODES[0x35],                              # 46
    ('UNK48',        'imm_16 imm_16'),          # 48
    ('UNK4A',        'addr_24'),                # 4A
    ('UNK4C',        'addr_24'),                # 4C
    OPCODES_WAITED[0x0C-0x04],                  # 4E
    OPCODES_WAITED[0x0D-0x04],                  # 50
    OPCODES_WAITED[0x0E-0x04],                  # 52
    OPCODES_WAITED[0x0F-0x04],                  # 54
    ('UNK56',        ''),                       # 56
    ('UNK58',        'imm_16'),                 # 58
    ('UNK5A',        'imm_16'),                 # 5A
    ('UNK5C',        'imm_16'),                 # 5C
)

BINOPS = ('AND', 'OR', 'ADD', 'XOR')

def snes2pc(addr):
    if addr >= 0xC00000:
        return addr - 0xC00000

    return ((addr & 0x3F0000) >> 1) | (addr & 0x7FFF)

def pc2snes(addr, super_mmc=False):
    if super_mmc:
        return addr + 0xC00000

    return ((addr & 0x3F8000) << 1) | (addr & 0x7FFF) | 0x8000

# Some epic tests because I was STUCK figuring out lorom conversion for 2 days straight like a dummy
'''
# SNES, PC
TESTS = (
    (0x008000, 0x000000),
    (0x00C000, 0x004000),
    (0x018000, 0x008000),
    (0x01C000, 0x00C000),
    (0x028000, 0x010000),
    (0x02C000, 0x014000),
    (0x038000, 0x018000),
    (0x03C000, 0x01C000)
)

for snes, pc in TESTS:
    print(f'snes2pc({snes:06X}) -> {snes2pc(snes):06X} (expect {pc:06X})')

print('-------------------------')
for snes, pc in TESTS:
    print(f'pc2snes({pc:06X}) -> {pc2snes(pc):06X} (expect {snes:06X})')
exit()
'''

class Disassembler(object):
    def __init__(self, rom_file, out_file, sym_file, asm_functions_file, header_offset, script_count, indent=4):
        self._indent = indent
        self.rom_file = rom_file
        self.out_file = out_file
        self.sym_file = sym_file
        self.asm_functions_file = asm_functions_file
        self.header_offset = header_offset
        self.script_count = script_count
        self.indentation = self._indent
        self.pc = 0
        self.was_linebreak = False
        self.force_label = False
        self.super_mmc = False # HACK: SA-1 stuff
        self.preset_asmcalls = []
        self.symbols = dict()
        self.asm_functions = dict()
        self.init_asm_functions()
        self.init_symbols()

    @property
    def snes_pc(self):
        return pc2snes(self.pc, self.super_mmc)

    def read_rom(self, amount, signed=False):
        b = self.rom_file.read(amount)
        return int.from_bytes(b, signed=signed, byteorder='little')

    def datatype_to_str(self, data_type, bytes_):
        value = int.from_bytes(bytes_, byteorder='little')
        if data_type == 'label_16':
            return self.symbols.get((self.snes_pc & 0xFF0000) | value, '${:04X}'.format(value))
        elif data_type == 'label_24':
            return self.symbols.get(value, '${:06X}'.format(value))
        elif data_type == 'imm_8':
            return '#${:02X}'.format(value)
        elif data_type == 'imm_16':
            return '#${:04X}'.format(value)
        elif data_type in ('imm_s8', 'imm_s16'):
            value = int.from_bytes(bytes_, signed=True, byteorder='little')
            return '#{}'.format(value)
        elif data_type in ('imm_u8', 'imm_u16'):
            return '#{}'.format(value)
        elif data_type == 'addr_16':
            return '${:04X}'.format(value)
        elif data_type == 'addr_24':
            return '${:06X}'.format(value)
        elif data_type == 'addr_32':
            value = ((value & 0xFFFF0000) >> 16) | ((value & 0xFFFF) << 16)  # addr_32 has a weird-ass format
            return '${:06X}'.format(value)
        elif data_type == 'obj_var':
            if value > 7:
                print(f'WARNING: INVALID OBJ_VAR OPERAND {value} @ {self.snes_pc:06X}')

            return 'VAR{}'.format(value)
        elif data_type in ('reg', 'nop'):
            return data_type.upper()
        else:
            raise TypeError('Unknown data type! ({})'.format(data_type))

    def try_add_label(self):
        label = self.symbols.get(self.snes_pc)

        if self.force_label:
            if not label:
                label = 'L_{:06X}'.format(self.snes_pc)
                self.symbols[self.snes_pc] = label

            label = '\n' + label

        if label:
            self.out_file.write(label + ':\n')

        return bool(label)

    def disassemble_all(self):
        l = list(self.symbols.keys())
        l.sort()

        self.bad_asmcall = set()
        for start in l:
            pcstart = snes2pc(start)
            self.rom_file.seek(pcstart + self.header_offset)
            self.pc = self.rom_file.tell()

            self.super_mmc = start >= 0xC00000

            while self.snes_pc in self.traversed:
                self.traversed.remove(self.snes_pc)

                was_label = self.try_add_label()
                self.was_linebreak = was_label or self.was_linebreak
                self.force_label = False

                opcode = self.read_rom(1)
                self.disasm_opcode(opcode)
                self.force_label = opcode in (0x00, 0x01, 0x09, 0x0C, 0x0D, 0x0E)
                self.pc = self.rom_file.tell()
                if self.force_label:
                    break

        l = list(self.bad_asmcall)
        l.sort()
        for address in l:
            print(f"WARNING: I DON'T KNOW ANYTHING ABOUT ASMCALL ${address:06X}!")

    def disasm_opcode(self, op_byte):
        indentation = ' ' * self.indentation

        waited = None
        opcode = op_byte
        if opcode >= 0x40:
            waited = opcode & 0x0F
            opcode = ((opcode & 0xF0) >> 4) - 0x04 # Get the actual opcode from the "waited opcode" code
            valid = True
        else:
            valid = (opcode < len(OPCODES))

        if not valid:
            to_write = (indentation + '.byte'.ljust(12) + '${:02X}'.format(opcode)).ljust(40 + len(indentation))
            to_write += '; {:06X}/{:02X}\n'.format(self.snes_pc, opcode)
            self.out_file.write(to_write)
            return

        op_addr = self.snes_pc

        if waited is None:
            mnemonic, types = OPCODES[opcode]
        else:
            mnemonic, types = OPCODES_WAITED[opcode]

        types = types.split()

        bytes_ = bytearray([op_byte])
        operands = []
        for data_type in types:
            b = self.rom_file.read(DATA_TYPE_SIZES[data_type])
            bytes_ += b
            operands.append(self.datatype_to_str(data_type, b))

        if waited is not None:
            operands.append(('' if len(operands) == 0 else ' ') + f'WAIT #{waited}')

        if not self.was_linebreak:
            mnemonic = '\n' + mnemonic  # Add leading newline if previous line didn't have a line break
            self.was_linebreak = True

        comment = ''
        extra = ''

        if mnemonic in ('ASMCALL', 'PRESETCALL'):
            if mnemonic == 'PRESETCALL':
                preset_id = bytes_[1]
                if preset_id >= len(self.preset_asmcalls):
                    address = -1 # Horrible hacks incoming!!!!!!
                    comment = ' // BAD PRESETCALL'
                    print(f'WARNING: BAD PRESETCALL: {preset_id:02X} @ {self.snes_pc:06X}')
                else:
                    address = self.preset_asmcalls[preset_id]
                    comment = f' // ASMCALL ${address:06X}'
            else:
                comment = ''
                address = int.from_bytes(bytes_[1:], byteorder='little')

            asm_func = self.asm_functions.get(address, None)
            if asm_func:
                DIRECTIVES = ('.byte', '.word', '.long', '.dword')
                if asm_func['comment']:
                    comment += ' // ' + asm_func['comment']

                # Fucking hell this is horrible
                for p in asm_func['params']:
                    if p == 'varargs':
                        count = self.read_rom(1)

                        self.pc = self.rom_file.tell()
                        extra += (indentation + '.byte'.ljust(12) + str(count)).ljust(40 + len(indentation))
                        extra += '; {:06X}/{:02X}\n'.format(self.snes_pc, count)

                        for i in range(count):
                            self.pc = self.rom_file.tell()
                            b = self.rom_file.read(2)
                            addr = int.from_bytes(b, byteorder='little')
                            extra += (indentation + '.word'.ljust(12) + str(addr)).ljust(40 + len(indentation))
                            extra += '; {:06X}/{}\n'.format(self.snes_pc, b.hex().upper())
                    else:
                        self.pc = self.rom_file.tell()
                        data_size = DATA_TYPE_SIZES[p]
                        b = self.rom_file.read(data_size)
                        arg = self.datatype_to_str(p, b)
                        arg = arg.replace('#', '')
                        extra += (indentation + DIRECTIVES[data_size - 1].ljust(12) + arg).ljust(40 + len(indentation))
                        extra += '; {:06X}/{}\n'.format(self.snes_pc, b.hex().upper())

            elif address not in self.bad_asmcall:
                self.bad_asmcall.add(address)
        elif mnemonic == 'BINOP':
            op = bytes_[1 + DATA_TYPE_SIZES[types[0]]] # Ugh.

            if op in (0, 1, 2, 3):
                del operands[1]
                mnemonic = mnemonic.replace('BINOP', BINOPS[op])

                if op == 2:  # ADD, change operand type from HEXADECIMAL immediate to DECIMAL immediate
                    data_type = 'imm_s8' if opcode == 0x1D else 'imm_s16'
                    size = DATA_TYPE_SIZES[data_type]
                    self.rom_file.seek(-size, os.SEEK_CUR)
                    operands[-1] = self.datatype_to_str(data_type, self.rom_file.read(size))
        elif mnemonic in ('MULTIJMP', 'MULTIJSR'):
            count = bytes_[1]

            for i in range(count):
                self.pc = self.rom_file.tell()
                b = self.rom_file.read(2)
                addr = self.datatype_to_str('label_16', b)
                extra += (indentation + '.word'.ljust(12) + addr).ljust(40 + len(indentation))
                extra += '; {:06X}/{}\n'.format(self.snes_pc, b.hex().upper())
        elif mnemonic in ('END', 'RTL', 'HALT', 'ENDTASK', 'RTS'):
            self.indentation = self._indent
            indentation = ' ' * self.indentation
            self.was_linebreak = True
        elif mnemonic == 'LOOP':
            self.indentation += self._indent
        elif mnemonic == 'ENDLOOP':
            self.indentation = max(self._indent, self.indentation - self._indent)
            indentation = ' ' * self.indentation
        elif mnemonic in ('JML', 'JMP'):
            self.was_linebreak = True
            self.indentation = max(self._indent, self.indentation - self._indent)

        to_write = (indentation + mnemonic.ljust(12) + ','.join(operands)).ljust(40 + len(indentation))
        to_write += '; {:06X}/{} {}\n'.format(op_addr, bytes_.hex().upper(), comment)
        self.out_file.write(to_write + extra)

    def init_symbols(self):
        self.traversed = set()
        self.traverse_queue = [] # wtf...

        if self.sym_file:
            self.parse_sym_file()

        # Read preset ASMCALLs...
        self.rom_file.seek(0x384D + self.header_offset)
        for i in range(24):
            self.preset_asmcalls.append(self.read_rom(3))

        # Now onto the script themselves
        self.rom_file.seek(0x3895 + self.header_offset)

        # Add default symbols for each script entry point, if they've not been defined
        for i in range(script_count):
            address = self.read_rom(4) & 0xFFFFFF
            if address not in self.symbols:
                print(f'Script{i:04X} @ ${address:06X}')
                self.add_label(address, f'Script{i:04X}')

        while self.traverse_queue:
            address = self.traverse_queue.pop()
            self.traverse(address)

    def add_label(self, address, label, traverse=False):
        if (address >= 0x400000 and address < 0x808000) or (address < 0xC00000 and (address & 0xFFFF) < 0x8000):
            return

        if address not in self.symbols:
            self.symbols[address] = label
            self.traverse_queue.append(address)

    def traverse(self, start):
        old_pc = self.pc
        old_super_mmc = self.super_mmc

        if start < 0x8000: return

        address = snes2pc(start)
        self.rom_file.seek(address + self.header_offset)
        self.pc = self.rom_file.tell()

        self.super_mmc = start >= 0xC00000

        while self.snes_pc not in self.traversed:
            op_byte = self.read_rom(1)

            opcode = op_byte
            if opcode >= 0x40:
                waited = True
                opcode = ((opcode & 0xF0) >> 4) - 0x04  # Get the actual opcode from the "waited opcode" code
                valid = True
            else:
                waited = False
                valid = (opcode < len(OPCODES))

            if not valid:
                break

            self.traversed.add(self.snes_pc)

            if op_byte & 0xF0 in (0xC0, 0xD0): # ASMCALL/PRESETCALL
                if op_byte & 0xF0 == 0xD0: # PRESETCALL
                    preset_id = self.read_rom(1)
                    if preset_id < len(self.preset_asmcalls):
                        addr = self.preset_asmcalls[preset_id]
                    else:
                        addr = -1 # HACK: Dummy
                else: # ASMCALL
                    addr = self.read_rom(3)

                asm_func = self.asm_functions.get(addr, None)
                if asm_func:
                    for p in asm_func['params']:
                        if p == 'varargs':
                            count = self.read_rom(1)
                            self.rom_file.read(count*2)  # Read and discard bytes
                        else:
                            data_size = DATA_TYPE_SIZES[p]
                            b = self.read_rom(data_size)  # Read and discard bytes
                            if p == 'label_24':
                                self.add_label(b, f'L_{b:06X}')
            elif op_byte in (0x0B, 0x0F):  # MULTIJSR/MULTIJMP
                count = self.read_rom(1)
                for i in range(count):
                    addr = (self.snes_pc & 0xFF0000) | self.read_rom(2)
                    self.add_label(addr, f'L_{addr:06X}')
            else:
                if not waited:
                    types = OPCODES[opcode][1].split()
                else:
                    types = OPCODES_WAITED[opcode][1].split()

                for data_type in types:
                    if data_type == 'label_16':
                        addr = (self.snes_pc & 0xFF0000) | self.read_rom(2)
                        self.add_label(addr, f'L_{addr:06X}')
                    elif data_type == 'label_24':
                        addr = self.read_rom(3)
                        self.add_label(addr, f'L_{addr:06X}')
                    else:
                        self.rom_file.read(DATA_TYPE_SIZES[data_type])  # Read and discard bytes

            self.pc = self.rom_file.tell()
            if op_byte in (0x00, 0x01, 0x09, 0x0C, 0x0D, 0x0E):
                break

        self.rom_file.seek(old_pc)
        self.pc = self.rom_file.tell()
        self.super_mmc = old_super_mmc

    def parse_sym_file(self):
        for i, line in enumerate(self.sym_file):
            pre_comment = line.split(';', maxsplit=1)[0].strip()  # Get everything on the line before the comment
            if '=' in pre_comment:
                label, str_address = [s.strip() for s in pre_comment.split('=', maxsplit=1)]

                if not all(c in LABEL_CHARSET for c in label):
                    print('Ignoring line {} from {}: Invalid label name ({})'.format(i, self.sym_file.name, label), file=sys.stderr)
                    continue

                try:
                    address = int(str_address, 16)
                    self.symbols[address] = label
                except ValueError:
                    print('Ignoring line {} from {}: Invalid address ({})'.format(i, self.sym_file.name, str_address), file=sys.stderr)
            elif pre_comment:
                print('Ignoring line {} from {}: Invalid line'.format(i, self.sym_file.name), file=sys.stderr)

    def init_asm_functions(self):
        if not self.asm_functions_file:
            return

        address = None
        asm_function = None
        for i, line in enumerate(self.asm_functions_file):
            pre_comment = line.split(';', maxsplit=1)[0].strip()  # Get everything on the line before the comment
            if '=' in pre_comment:
                if address is None:
                    print('Ignoring line {} from {}: Attribute assignment without ASM_FUNCTION directive'.format(i, self.asm_functions_file.name), file=sys.stderr)
                    continue

                key, value = [s.strip() for s in pre_comment.split('=', maxsplit=1)]                
                if key == 'COMMENT':
                    self.asm_functions[address]['comment'] = value
                elif key == 'PARAMS':
                    self.asm_functions[address]['params'] = [s.strip() for s in value.split(',')]
                else:
                    print('Ignoring line {} from {}: Invalid attribute ({})'.format(i, self.asm_functions_file.name, key), file=sys.stderr)
            elif pre_comment:
                directive, arg = [s.strip() for s in pre_comment.split(maxsplit=1)]
                if directive == 'ASM_FUNCTION':
                    try:
                        address = int(arg, 16)
                        self.asm_functions[address] = {'comment': '', 'params': []}
                    except ValueError:
                        print('Ignoring line {} from {}: Invalid address ({})'.format(i, self.asm_functions_file.name, arg), file=sys.stderr)
                else:
                    print('Ignoring line {} from {}: Unknown directive ({})'.format(i, self.asm_functions_file.name, directive), file=sys.stderr)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--symfile', help='the symbols definition file')
    parser.add_argument('-a', '--asmfuncfile', help='the asm functions definition file')
    parser.add_argument('romfile', help='the Earthbound or MOTHER 2 ROM file')
    parser.add_argument('outfile', help='the output file')
    args = parser.parse_args()

    rom_size = os.path.getsize(args.romfile)
    header_offset = rom_size % 0x010000
    if rom_size < 0x100000 or (header_offset != 0 and header_offset != 512):
        print("The file {} doesn't look like a valid Kirby Super Star ROM!".format(args.romfile), file=sys.stderr)
        sys.exit(1)

    rom_file = open(args.romfile, 'rb')
    out_file = open(args.outfile, 'w')
    sym_file = open(args.symfile, 'r') if args.symfile else None
    asm_funcs_file = open(args.asmfuncfile, 'r') if args.asmfuncfile else None

    rom_file.seek(0x7FC0 + header_offset)
    rom_name = rom_file.read(21)

    if rom_name != b"KIRBY SUPER DELUXE".ljust(21):
        print("The file {} doesn't look like a valid Kirby Super Star ROM!".format(args.romfile), file=sys.stderr)
        sys.exit(1)

    script_count = LAST_SCRIPT
    disassembler = Disassembler(rom_file, out_file, sym_file, asm_funcs_file, header_offset, script_count, indent=4)
    disassembler.disassemble_all()

    rom_file.close()
    out_file.close()
    if sym_file:
        sym_file.close()

    with open('symbols_out.txt', 'w') as f:
        for k, v in disassembler.symbols.items():
            f.write('{:06X}: {}\n'.format(k, v))
