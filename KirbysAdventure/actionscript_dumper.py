#!/usr/bin/python3

# Some of the code you'll see here is bad, but it works.

import argparse
import os
import string
import sys

INES_SIZE = 16

LABEL_CHARSET = string.ascii_letters + string.digits + '_'  # Valid characters for labels

LAST_SCRIPT = 112  # Amount of scripts

# In the format (START, END)
SCRIPT_BLOCKS = (
    (0x14*0x2000 + 0x0000, 0x14*0x2000 + 0x00D5),
    (0x16*0x2000 + 0x0A3A, 0x16*0x2000 + 0x0A96),
    (0x16*0x2000 + 0x0B36, 0x16*0x2000 + 0x0B49),
    (0x16*0x2000 + 0x0BDC, 0x16*0x2000 + 0x0BF8),
    (0x16*0x2000 + 0x0C72, 0x16*0x2000 + 0x0C8D),
    (0x16*0x2000 + 0x0C9A, 0x16*0x2000 + 0x0CBD),
    (0x16*0x2000 + 0x0D15, 0x16*0x2000 + 0x0D1F),
    (0x16*0x2000 + 0x0D3C, 0x16*0x2000 + 0x0D63),
    (0x16*0x2000 + 0x0D97, 0x16*0x2000 + 0x0DEA),
    (0x18*0x2000 + 0x0311, 0x18*0x2000 + 0x040C),
    (0x3D*0x2000 + 0x0000, 0x3D*0x2000 + 0x02D5),
    (0x3D*0x2000 + 0x09EB, 0x3D*0x2000 + 0x0A4E),
    (0x3D*0x2000 + 0x09EB, 0x3D*0x2000 + 0x0A4E),
    (0x3D*0x2000 + 0x1F50, 0x3D*0x2000 + 0x1F57),
)

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
    'obj_var':  1,  # Object variable (i.e. VAR0, VAR1, ..., VAR9)
    'reg':      0,  # The work register
    'nop':      0,  # Special, used only by opcode 0x0F (ONTICK NOP)
}

# (mnemonic, data types separated by spaces)
OPCODES = (
    ('END',         ''),                       # 00
    ('LOOP',        'imm_u8'),                 # 01
    ('ENDLOOP',     ''),                       # 02
    ('JML',         'label_24'),               # 03
    ('JSL',         'label_24'),               # 04
    ('RTL',         ''),                       # 05
    ('WAIT',        'imm_u8'),                 # 06
    ('TASK',        'label_16'),               # 07
    ('ONTICK',      'addr_24'),                # 08
    ('HALT',        ''),                       # 09
    ('JEQ',         'label_16'),               # 0A
    ('JNE',         'label_16'),               # 0B
    ('ENDTASK',     ''),                       # 0C
    ('MOV',         'obj_var imm_8'),          # 0D
    ('ONTICK',      'nop'),                    # 0E
    ('MULTIJMP',    'imm_u8'),                 # 0F
    ('MULTIJSR',    'imm_u8'),                 # 10
    ('MOV.b',       'addr_16 imm_8'),          # 11
    ('ENDLASTTASK', ''),                       # 12
    ('BINOP',       'obj_var imm_u8 imm_8'),   # 13
    ('BREAKEQ',     'label_16'),               # 14
    ('BREAKNE',     'label_16'),               # 15
    ('BINOP',       'addr_16 imm_u8 imm_8'),   # 16
    ('JMP',         'label_16'),               # 17
    ('JSR',         'label_16'),               # 18
    ('RTS',         ''),                       # 19
    ('SPRITEMAP',   'addr_24'),                # 1A
    ('MOV',         'reg imm_8'),              # 1B
    ('MOV',         'reg addr_16'),            # 1C
    ('MOV',         'obj_var reg'),            # 1D
    ('MOV',         'reg obj_var'),            # 1E
    ('WAIT',        'obj_var'),                # 1F
    ('ONDRAW',      'addr_16'),                # 20
    ('ONPOSITION',  'addr_16'),                # 21
    ('LOOP',        'reg'),                    # 22
    ('ONMOVE',      'addr_16'),                # 23
    ('SETPOSE',     'obj_var'),                # 24
    ('BINOP',       'reg imm_u8 imm_8'),       # 25
    ('ASMCALL.l',   'addr_24'),                # 26
    ('MOV.w',       'addr_16 imm_16'),         # 27
    ('SETBANK',     'imm_8'),                  # 28
    ('MULTICALL',   'imm_u8'),                 # 29
    ('SETXPOS',     'imm_16'),                 # 2A
    ('SETYPOS',     'imm_16'),                 # 2B
    ('ADDXPOS',     'imm_s16'),                # 2C
    ('ADDYPOS',     'imm_s16'),                # 2D
    ('ADDXVEL',     'imm_16'),                 # 2E
    ('ADDYVEL',     'imm_16'),                 # 2F
    ('UNK30',       'imm_8 imm_8'),            # 30
    ('UNK31',       'imm_8 imm_8'),            # 31
    ('UNK32',       'imm_8 imm_8'),            # 32
    ('UNK33',       'imm_8 imm_8'),            # 33
    ('UNK34',       'imm_8 imm_8'),            # 34
    ('UNK35',       'imm_8 imm_8'),            # 35
    ('UNK36',       'imm_8 imm_8'),            # 36
    ('UNK37',       'imm_8 imm_8'),            # 37
    ('ZEROVEL',     ''),                       # 38
    ('UNK39',       'imm_8'),                  # 39
    ('SETZPOS',     'imm_16'),                 # 3A
    ('ADDZPOS',     'imm_s16'),                # 3B
    ('SETZVEL',     'imm_16'),                 # 3C
    ('ADDZVEL',     'imm_16'),                 # 3D
    ('MULTIJSL',    'imm_u8'),                 # 3E
)

OPCODES_WAITED = (
    ('SETPOSE', 'imm_8'),   # 5x
    ('ADDPOSE', 'imm_s8'),  # 6x
    ('INCPOSE', ''),        # 7x
    ('DECPOSE', ''),        # 8x
    ('INC2POSE', ''),       # 9x
    ('DEC2POSE', ''),       # Ax
    ('SETXVEL', 'imm_16'),  # Bx
    ('SETYVEL', 'imm_16'),  # Cx
    ('ASMCALL', 'addr_16'), # Dx
)

BINOPS = ('AND', 'OR', 'ADD', 'XOR')

class Disassembler(object):
    def __init__(self, rom_file, out_file, sym_file, asm_functions_file, script_count, indent=4):
        self._indent = indent
        self.rom_file = rom_file
        self.out_file = out_file
        self.sym_file = sym_file
        self.asm_functions_file = asm_functions_file
        self.script_count = script_count
        self.indentation = self._indent
        self.pc = 0
        self.was_linebreak = False
        self.force_label = False
        self.symbols = dict()
        self.asm_functions = dict()
        self.init_asm_functions()
        self.init_symbols()

    @property
    def nes_pc(self):
        pc = self.pc - INES_SIZE
        return 0xA000 + (((pc >> 13) << 16) | (pc & 0x1FFF))

    def read_rom(self, amount, signed=False, byteorder='little'):
        b = self.rom_file.read(amount)
        return int.from_bytes(b, signed=signed, byteorder=byteorder)

    def datatype_to_str(self, data_type, bytes_):
        value = int.from_bytes(bytes_, byteorder='little')
        if data_type == 'label_16':
            return self.symbols.get((self.nes_pc & 0xFF0000) | value, '${:04X}'.format(value))
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
            if value > 10:
                print(f'WARNING: INVALID OBJ_VAR OPERAND {value} @{self.nes_pc:06X}')

            return 'VAR{}'.format(value)
        elif data_type in ('reg', 'nop'):
            return data_type.upper()
        else:
            raise TypeError('Unknown data type! ({})'.format(data_type))

    def try_add_label(self):
        label = self.symbols.get(self.nes_pc)

        if self.force_label:
            if not label:
                label = 'L_{:06X}'.format(self.nes_pc)
                self.symbols[self.nes_pc] = label

            label = '\n' + label

        if label:
            self.out_file.write(label + ':\n')

        return bool(label)

    def disassemble_all(self):
        l = list(self.symbols.keys())
        l.sort()

        self.bad_asmcall = set()
        for start in l:
        #for start, end in SCRIPT_BLOCKS:
            #end += INES_SIZE
            #size += end - start
            pcstart = (start >> 16) * 0x2000 + (start & 0x1FFF)
            self.rom_file.seek(pcstart + INES_SIZE)
            self.pc = self.rom_file.tell()

            while self.nes_pc in self.traversed:
                self.traversed.remove(self.nes_pc)

                was_label = self.try_add_label()
                self.was_linebreak = was_label or self.was_linebreak
                self.force_label = False

                opcode = self.read_rom(1)
                self.disasm_opcode(opcode)
                self.force_label = opcode in (0x00, 0x03, 0x05, 0x09, 0x0C, 0x17, 0x19)
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
        if opcode >= 0x50:
            waited = opcode & 0x0F
            opcode = ((opcode - 0x50) >> 4)  # Get the actual opcode from the "waited opcode" code
            valid = (opcode <= 0x0D-0x05)
        else:
            valid = (opcode < len(OPCODES))

        if not valid:
            to_write = (indentation + '.byte'.ljust(12) + '${:02X}'.format(op_byte)).ljust(40 + len(indentation))
            to_write += '; {:06X}/{:02X}\n'.format(self.nes_pc, op_byte)
            self.out_file.write(to_write)
            return

        op_addr = self.nes_pc

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

        if waited is not None and waited != 0:
            operands.append(('' if len(operands) == 0 else ' ') + f'WAIT #{waited}')

        if not self.was_linebreak:
            mnemonic = '\n' + mnemonic  # Add leading newline if previous line didn't have a line break
            self.was_linebreak = True

        comment = ''
        extra = ''

        if mnemonic in ('ASMCALL', 'ASMCALL.l'):
            if mnemonic == 'ASMCALL.l':
                address = int.from_bytes(bytes_[1:], byteorder='little')
            elif self.pc in self.lower_asmcalls:
                address = self.lower_asmcalls[self.pc]
            else:
                address = int.from_bytes(bytes_[1:], byteorder='little')
                if address < 0xC000:
                    address = (self.nes_pc & 0xFF0000) | address

            asm_func = self.asm_functions.get(address, None)
            if asm_func:
                DIRECTIVES = ('.byte', '.word', '.long', '.dword')
                comment = ' // ' + asm_func['comment'] if asm_func['comment'] else ''

                # Fucking hell this is horrible
                for p in asm_func['params']:
                    if p == 'varargs':
                        count = self.read_rom(1)

                        self.pc = self.rom_file.tell()
                        extra += (indentation + '.byte'.ljust(12) + str(count)).ljust(40 + len(indentation))
                        extra += '; {:06X}/{:02X}\n'.format(self.nes_pc, count)

                        for i in range(count):
                            self.pc = self.rom_file.tell()
                            b = self.rom_file.read(2)
                            addr = int.from_bytes(b, byteorder='little')
                            extra += (indentation + '.word'.ljust(12) + str(addr)).ljust(40 + len(indentation))
                            extra += '; {:06X}/{}\n'.format(self.nes_pc, b.hex().upper())
                    else:
                        self.pc = self.rom_file.tell()
                        data_size = DATA_TYPE_SIZES[p]
                        b = self.rom_file.read(data_size)
                        arg = self.datatype_to_str(p, b)
                        arg = arg.replace('#', '')
                        extra += (indentation + DIRECTIVES[data_size - 1].ljust(12) + arg).ljust(40 + len(indentation))
                        extra += '; {:06X}/{}\n'.format(self.nes_pc, b.hex().upper())

            elif address not in self.bad_asmcall:
                self.bad_asmcall.add(address)
        elif mnemonic == 'ONTICK':
            address = int.from_bytes(bytes_[1:], byteorder='little')
            asm_func = self.asm_functions.get(address, None)
            if asm_func and asm_func['comment']:
                comment = ' // ' + asm_func['comment']
        elif mnemonic == 'BINOP':
            # Now THIS is what I call hacky shit!
            if opcode == 0x25:
                op = bytes_[1]
            elif opcode == 0x13:
                op = bytes_[2]
            else:
                op = bytes_[3]

            if op in (0, 1, 2, 3):
                del operands[1]
                mnemonic = mnemonic.replace('BINOP', BINOPS[op])

                if op == 2:  # ADD, change operand type from HEXADECIMAL immediate to DECIMAL immediate
                    data_type = 'imm_s8'
                    size = DATA_TYPE_SIZES[data_type]
                    self.rom_file.seek(-size, os.SEEK_CUR)
                    operands[-1] = self.datatype_to_str(data_type, self.rom_file.read(size))
        elif mnemonic in ('MULTIJMP', 'MULTIJSR', 'MULTICALL', 'MULTIJSL'):
            # Hack to fix a programming mistake in the original actionscript!
            # The MULTIJMP instruction at $26A8CF is defined to expect 3 pointers, but 4 pointers are actually defined!
            if self.nes_pc == 0x26A8CF:
                count = 4
            else:
                count = bytes_[1]

            if mnemonic in ('MULTICALL', 'MULTIJSL'):
                data_type = 'label_24'
                directive = '.long'
                data_size = 3
            else:
                data_type = 'label_16'
                directive = '.word'
                data_size = 2

            for i in range(count):
                self.pc = self.rom_file.tell()
                b = self.rom_file.read(data_size)
                addr = self.datatype_to_str(data_type, b)
                extra += (indentation + directive.ljust(12) + addr).ljust(40 + len(indentation))
                extra += '; {:06X}/{}\n'.format(self.nes_pc, b.hex().upper())
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
        to_write += '; {:06X}/{}{}\n'.format(op_addr, bytes_.hex().upper(), comment)
        self.out_file.write(to_write + extra)

    def init_symbols(self):
        self.traversed = set()
        self.traverse_queue = [] # wtf...

        if self.sym_file:
            self.parse_sym_file()

        self.rom_file.seek(0x18*0x2000 + 0x00A7 + INES_SIZE)
        lo = self.rom_file.read(self.script_count)
        hi = self.rom_file.read(self.script_count)
        bank = self.rom_file.read(self.script_count)

        entry_points = set()

        self.lower_asmcalls = {}
        # Add default symbols for each script entry point, if they've not been defined
        for i in range(self.script_count):
            address = (bank[i] << 16) | (hi[i] << 8) | lo[i]
            entry_points.add(address)
            print(f'Script{i:02X} @ ${address:06X}')
            self.add_label(address, f'Script{i:02X}')

        self.rom_file.seek(0x21*0x2000 + 0x0CFF + INES_SIZE)
        lo = self.rom_file.read(0xEF)
        hi = self.rom_file.read(0xEF)
        bank = self.rom_file.read(0xEF)

        kirby_states = set()

        for i in range(0xEF):
            address = (bank[i] << 16) | (hi[i] << 8) | lo[i]
            kirby_states.add(address)
            print(f'KirbyState{i:02X} @ ${address:06X}')
            self.lower_prg = 0x21
            self.add_label(address, f'KirbyState{i:02X}')

        while self.traverse_queue:
            address = self.traverse_queue.pop()
            if address in entry_points:
                self.lower_prg = None
            elif address in kirby_states:
                self.lower_prg = 0x21

            self.traverse(address)

    def add_label(self, address, label, traverse=False):
        if (address >> 16) < 0x13 or (address >> 16) >= 0x3E or (address & 0xFFFF) < 0xA000 or (address & 0xFFFF) > 0xC000:
            return

        if address not in self.symbols:
            self.symbols[address] = label
            self.traverse_queue.append(address)

    def traverse(self, start):
        old_pc = self.pc

        if (start & 0xFFFF) >= 0xC000:
            return

        address = (start >> 16) * 0x2000 + (start & 0x1FFF)
        self.rom_file.seek(address + INES_SIZE)
        self.pc = self.rom_file.tell()

        while self.nes_pc not in self.traversed:
            op_byte = self.read_rom(1)

            opcode = op_byte
            if opcode >= 0x50:
                waited = True
                opcode = ((opcode - 0x50) >> 4) # Get the actual opcode from the "waited opcode" code
                valid = (opcode <= 0x0D-0x05)
            else:
                waited = False
                valid = (opcode < len(OPCODES))

            if not valid:
                break

            self.traversed.add(self.nes_pc)

            if op_byte == 0x07:  # TASK
                addr = (self.nes_pc & 0xFF0000) | self.read_rom(2)
                self.add_label(addr, f'TASK_{addr:06X}')
            elif (op_byte & 0xF0 == 0xD0) or op_byte == 0x26:  # ASMCALL/ASMCALL.l
                if op_byte == 0x26:
                    addr = self.read_rom(3)
                else:
                    addr = self.read_rom(2)
                    if addr >= 0x8000 and addr < 0xA000:
                        bank = self.lower_prg
                        if self.lower_prg is None:
                            print(f'WTF???? LOWER PRG IS NONE AND WE ENCOUNTERED ASMCALL {addr:04X}')
                            bank = self.nes_pc >> 16

                        addr = (bank << 16) | addr
                        self.lower_asmcalls[self.pc] = addr
                    elif addr < 0xC000:
                        addr = (self.nes_pc & 0xFF0000) | addr

                asm_func = self.asm_functions.get(addr, None)
                if asm_func:
                    for p in asm_func['params']:
                        if p == 'varargs':
                            count = self.read_rom(1)
                            self.rom_file.read(count*2)  # Read and discard bytes
                        else:
                            data_size = DATA_TYPE_SIZES[p]
                            b = self.rom_file.read(data_size)  # Read and discard bytes
            elif op_byte in (0x0F, 0x10):  # MULTIJMP/MULTIJSR
                count = self.read_rom(1)
                for i in range(count):
                    addr = (self.nes_pc & 0xFF0000) | self.read_rom(2)
                    self.add_label(addr, f'L_{addr:06X}')
            elif op_byte in (0x29, 0x3E): # MULTICALL/MULTIJSL
                count = self.read_rom(1)
                for i in range(count):
                    addr = self.read_rom(3)
                    self.add_label(addr, f'L_{addr:06X}')
            elif op_byte == 0x28: # SETBANK
                self.lower_prg = self.read_rom(1)
            else:
                if not waited:
                    types = OPCODES[opcode][1].split()
                else:
                    types = OPCODES_WAITED[opcode][1].split()

                for data_type in types:
                    if data_type == 'label_16':
                        addr = (self.nes_pc & 0xFF0000) | self.read_rom(2)
                        self.add_label(addr, f'L_{addr:06X}')
                    elif data_type == 'label_24':
                        addr = self.read_rom(3)
                        self.add_label(addr, f'L_{addr:06X}')
                    else:
                        self.rom_file.read(DATA_TYPE_SIZES[data_type])  # Read and discard bytes

            self.pc = self.rom_file.tell()
            if op_byte in (0x00, 0x03, 0x05, 0x09, 0x0C, 0x17, 0x19):
                break


        self.rom_file.seek(old_pc)
        self.pc = self.rom_file.tell()

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
                    self.add_label(address, label)
                    #self.symbols[address] = label
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
    parser.add_argument('romfile', help="the Kirby's Adventure ROM file")
    parser.add_argument('outfile', help='the output file')
    args = parser.parse_args()

    rom_size = os.path.getsize(args.romfile)
    if rom_size != 0xC0010:
        print("The file {} doesn't look like a valid Kirby's Adventure ROM!".format(args.romfile), file=sys.stderr)
        sys.exit(1)

    rom_file = open(args.romfile, 'rb')
    out_file = open(args.outfile, 'w')
    sym_file = open(args.symfile, 'r') if args.symfile else None
    asm_funcs_file = open(args.asmfuncfile, 'r') if args.asmfuncfile else None

    # TODO: Check if this is actually a Kirby's Adventure ROM (how??)

    disassembler = Disassembler(rom_file, out_file, sym_file, asm_funcs_file, LAST_SCRIPT, indent=4)
    disassembler.disassemble_all()

    rom_file.close()
    out_file.close()
    if sym_file:
        sym_file.close()

    with open('symbols_out.txt', 'w') as f:
        for k, v in disassembler.symbols.items():
            f.write('{:06X}: {}\n'.format(k, v))
