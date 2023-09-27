#!/usr/bin/python3

# Some of the code you'll see here is bad, but it works.

import argparse
import os
import string
import sys

LABEL_CHARSET = string.ascii_letters + string.digits + '_'  # Valid characters for labels

LAST_SCRIPT = 134  # Amount of scripts

SCRIPT_BLOCKS = (
    (0x00772B, 0x0077BB),
    (0x00C609, 0x00C737),
    (0x00C74A, 0x00C770),
    (0x00C783, 0x00C825)
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
    'obj_var':  1,  # Object variable (i.e. VAR0, VAR1, ..., VAR7)
    'reg':      0,  # The work register
    'nop':      0,  # Special, used only by opcode 0x0F (ONTICK NOP)
}

# (mnemonic, data types separated by spaces)
OPCODES = (
    ('END',         ''),
    ('STARTLOOP',   'imm_u8'),
    ('ENDLOOP',     ''),
    ('JML',         'label_24'),
    ('JSL',         'label_24'),
    ('RTL',         ''),
    ('WAIT',        'imm_u8'),
    ('ASMCALL',     'addr_24'),
    ('TASK',        'label_16'),
    ('ONTICK',      'addr_24'),
    ('HALT',        ''),
    ('JEQ',         'label_16'),
    ('JNE',         'label_16'),
    ('ENDTASK',     ''),
    ('BINOP.w',     'addr_16 imm_u8 imm_16'),  # BINOP with 16-bit memory value
    ('MOV',         'obj_var imm_16'),
    ('ONTICK',      'nop'),
    ('MULTIJMP',    'imm_u8'),
    ('MULTIJSR',    'imm_u8'),
    ('MOV.b',       'addr_16 imm_8'),
    ('UNK_TASK',    'imm_s8'),
    ('BINOP',       'obj_var imm_u8 imm_16'),  # BINOP with object variable
    ('MOV.w',       'addr_16 imm_16'),
    ('BREAKEQ',     'label_16'),
    ('BREAKNE',     'label_16'),
    ('BINOP.b',     'addr_16 imm_u8 imm_8'),   # BINOP with 8-bit memory value
    ('JMP',         'label_16'),
    ('JSR',         'label_16'),
    ('RTS',         ''),
    ('SETANIMPTR',  'addr_24'),
    ('MOV',         'reg imm_16'),
    ('MOV',         'reg addr_16'),
    ('WEIRD_1'      'imm_8'),        # Nonexistant instruction in Earthbound
    ('WEIRD_2',     'imm_8'),        # Nonexistant instruction in Earthbound
    ('WEIRD_3',     'imm_8'),        # Nonexistant instruction in Earthbound
    ('MOV',         'obj_var reg'),
    ('MOV',         'reg obj_var'),
    ('WAIT',        'obj_var'),
    # SPECIAL INSTRUCTIONS BEGIN
    ('SETANIM',     'imm_s8'),
    ('SETXPOS',     'imm_16'),
    ('SETYPOS',     'imm_16'),
    ('ADDXPOS',     'imm_s16'),
    ('ADDYPOS',     'imm_s16'),
    ('SETXVEL',     'imm_16'),
    ('SETYVEL',     'imm_16'),
    ('ADDXVEL',     'imm_16'),
    ('ADDYVEL',     'imm_16'),
    ('BGHDISP',     'imm_u8 imm_16'),  # Set background horizontal displacement          (Earthbound: UNK31)
    ('BGVDISP',     'imm_u8 imm_16'),  # Set background vertical displacement            (Earthbound: UNK32)
    ('BGHDISPVEL',  'imm_u8 imm_16'),  # Set background horizontal displacement velocity (Earthbound: UNK33)
    ('BGVDISPVEL',  'imm_u8 imm_16'),  # Set background vertical displacement velocity   (Earthbound: UNK34)
    ('UNK_35',      'imm_u8 imm_16'),  # UNK35 in Earthbound
    ('UNK_36',      'imm_u8 imm_16'),  # UNK36 in Earthbound
    ('INCANIM',     ''),
    ('DECANIM',     ''),
    ('ADDANIM',     'imm_s8'),
    ('UNK_37',      'imm_8 imm_16'),   # UNK37 in Earthbound
    ('UNK_38',      'imm_8 imm_16'),   # UNK38 in Earthbound
    ('ZEROVEL',     ''),
    ('ZRBGDISPVEL', 'imm_8'),          # Zero background displacement velocity (Earthbound: UNK3A)
    ('SETZPOS',     'imm_16'),
    ('ADDZPOS',     'imm_s16'),
    ('SETZVEL',     'imm_16'),
    ('ADDZVEL',     'imm_16'),
)

BINOPS = ('AND', 'OR', 'ADD')

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
        self.symbols = dict()
        self.asm_functions = dict()
        self.init_asm_functions()
        self.init_symbols()

    @property
    def snes_pc(self):
        addr = self.pc
        bank = addr >> 15
        addr = (addr & 0x7FFF) + ((bank & 0x2F) * 0x010000) | 0x8000

        return addr

    def read_rom(self, amount, signed=False):
        b = self.rom_file.read(amount)
        return int.from_bytes(b, signed=signed, byteorder='little')

    def datatype_to_str(self, data_type, bytes_):
        value = int.from_bytes(bytes_, byteorder='little')
        if data_type == 'label_16':
            bank_mask = self.snes_pc & 0xFF0000
            return self.symbols.get(bank_mask | value, '${:04X}'.format(value))
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
            if value > 3:
                print('WARNING: INVALID OBJ_VAR OPERAND:', value)

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
        self.force_label = False  # For first
        for start, end in SCRIPT_BLOCKS:
            self.rom_file.seek(start)
            self.pc = self.rom_file.tell()

            while self.pc < end:
                was_label = self.try_add_label()
                self.was_linebreak = was_label or self.was_linebreak
                self.force_label = False

                opcode = self.read_rom(1)
                self.disasm_opcode(opcode)
                self.force_label = opcode in (0x00, 0x03, 0x05, 0x0A, 0x0E, 0x1A, 0x1C)
                self.pc = self.rom_file.tell()

    def disasm_opcode(self, op_byte):
        indentation = ' ' * self.indentation

        waited = 0
        opcode = op_byte
        if opcode >= 0x30:
            waited = opcode & 0x07
            opcode = (((opcode - 0x30) & 0xF8) >> 3) + 0x26

        if opcode >= len(OPCODES):
            to_write = (indentation + '.byte'.ljust(12) + '${:02X}'.format(opcode)).ljust(40 + len(indentation))
            to_write += '; {:06X}/{:02X}\n'.format(self.snes_pc, opcode)
            self.out_file.write(to_write)
            return

        op_addr = self.snes_pc

        mnemonic, types = OPCODES[opcode]
        types = types.split()

        bytes_ = bytearray([op_byte])
        operands = []
        for data_type in types:
            b = self.rom_file.read(DATA_TYPE_SIZES[data_type])
            bytes_ += b
            operands.append(self.datatype_to_str(data_type, b))

        if waited > 0:
            operands.append('WAIT #{}'.format(waited))

        if not self.was_linebreak:
            mnemonic = '\n' + mnemonic  # Add leading newline if previous line didn't have a line break
            self.was_linebreak = True

        comment = ''
        extra = ''

        if opcode == 0x07:  # ASMCALL
            address = int.from_bytes(bytes_[1:], byteorder='little')
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
                        
            else:
                print("WARNING: I DON'T KNOW ANYTHING ABOUT ASM FUNCTION {:06X}".format(address))
        elif opcode in (0x0E, 0x15, 0x19):  # BINOP
            # Now THIS is what I call hacky shit!
            if opcode == 0x15:
                op = bytes_[2]
            else:
                op = bytes_[3]

            if op in (0, 1, 2):
                del operands[1]
                mnemonic = mnemonic.replace('BINOP', BINOPS[op])
                
                if op == 2:  # ADD, change operand type from HEXADECIMAL immediate to DECIMAL immediate
                    data_type = 'imm_s8' if opcode == 0x19 else 'imm_s16'
                    size = DATA_TYPE_SIZES[data_type]
                    self.rom_file.seek(-size, os.SEEK_CUR)
                    operands[-1] = self.datatype_to_str(data_type, self.rom_file.read(size))
        elif opcode in (0x11, 0x12):  # MULTIJMP, MULTIJSR
            count = bytes_[1]

            for i in range(count):
                self.pc = self.rom_file.tell()
                b = self.rom_file.read(2)
                addr = self.datatype_to_str('label_16', b)
                extra += (indentation + '.word'.ljust(12) + addr).ljust(40 + len(indentation))
                extra += '; {:06X}/{}\n'.format(self.snes_pc, b.hex().upper())
        elif opcode in (0x00, 0x05, 0x0A, 0x0D, 0x1C):  # END, RTL, HALT, ENDTASK, RTS
            self.indentation = self._indent
            indentation = ' ' * self.indentation
            self.was_linebreak = True
        elif opcode == 0x01:  # STARTLOOP
            self.indentation += self._indent
        elif opcode == 0x02:  # ENDLOOP
            self.indentation = max(self._indent, self.indentation - self._indent)
            indentation = ' ' * self.indentation
        elif opcode in (0x03, 0x1A):  # JML, JMP
            self.was_linebreak = True
            self.indentation = max(self._indent, self.indentation - self._indent)

        to_write = (indentation + mnemonic.ljust(12) + ','.join(operands)).ljust(40 + len(indentation))
        to_write += '; {:06X}/{}{}\n'.format(op_addr, bytes_.hex().upper(), comment)
        self.out_file.write(to_write + extra)

    def init_symbols(self):
        if self.sym_file:
            self.parse_sym_file()

        # Seek to the start of the "script entry points" pointer table
        self.rom_file.seek(0x002785 + self.header_offset)

        # Add default symbols for each script entry point, if they've not been defined
        for i in range(self.script_count):
            address = self.read_rom(3)
            if address not in self.symbols:
                self.symbols[address] = 'Script{:04d}'.format(i)

        # BAD STUFF AHEAD, LOTS OF DUPLICATE CODE FROM "disasm_opcode"
        for start, end in SCRIPT_BLOCKS:
            self.rom_file.seek(start)
            self.pc = self.rom_file.tell()

            while self.pc < end:
                opcode = self.read_rom(1)

                if opcode >= 0x30:
                    opcode = (((opcode - 0x30) & 0xF8) >> 3) + 0x26  # Get the actual opcode from the "waited opcode" code

                if opcode >= len(OPCODES):
                    continue

                if opcode == 0x08:  # TASK
                    bank_mask = self.snes_pc & 0xFF0000
                    addr = bank_mask | self.read_rom(2)
                    if addr not in self.symbols:
                        self.symbols[addr] = f'TASK_{addr:06X}'
                elif opcode == 0x07:  # ASMCALL
                    addr = self.read_rom(3)
                    asm_func = self.asm_functions.get(addr, None)
                    if asm_func:
                        for p in asm_func['params']:
                            if p == 'varargs':
                                count = self.read_rom(1)
                                self.rom_file.read(count*2)  # Read and discard bytes
                            else:
                                data_size = DATA_TYPE_SIZES[p]
                                b = self.rom_file.read(data_size)  # Read and discard bytes
                elif opcode in (0x11, 0x12):  # MULTIJMP/MULTIJSR
                    count = self.read_rom(1)
                    self.rom_file.read(count*2)  # Read and discard bytes
                else:
                    types = OPCODES[opcode][1].split()
                    for data_type in types:
                        if data_type == 'label_16':
                            bank_mask = self.snes_pc & 0xFF0000
                            addr = bank_mask | self.read_rom(2)
                            if addr not in self.symbols:
                                self.symbols[addr] = f'L_{addr:06X}'
                        elif data_type == 'label_24':
                            addr = self.read_rom(3)
                            if addr not in self.symbols:
                                self.symbols[addr] = f'L_{addr:06X}'
                        else:
                            self.rom_file.read(DATA_TYPE_SIZES[data_type])  # Read and discard bytes

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
    parser.add_argument('romfile', help="the HyperZone ROM file")
    parser.add_argument('outfile', help='the output file')
    args = parser.parse_args()

    rom_size = os.path.getsize(args.romfile)
    header_offset = rom_size % 0x010000
    if rom_size < 0x080000 or (header_offset != 0 and header_offset != 512):
        print("The file {} doesn't look like a valid HyperZone ROM!".format(args.romfile), file=sys.stderr)
        sys.exit(1)

    rom_file = open(args.romfile, 'rb')
    out_file = open(args.outfile, 'w')
    sym_file = open(args.symfile, 'r') if args.symfile else None
    asm_funcs_file = open(args.asmfuncfile, 'r') if args.asmfuncfile else None

    rom_file.seek(0x7FC0 + header_offset)
    rom_name = rom_file.read(21)

    if rom_name != b'HYPER ZONE'.ljust(21):
        print("The file {} doesn't look like a valid HyperZone ROM!".format(args.romfile), file=sys.stderr)
        sys.exit(1)

    disassembler = Disassembler(rom_file, out_file, sym_file, asm_funcs_file, header_offset, LAST_SCRIPT, indent=4)
    disassembler.disassemble_all()

    rom_file.close()
    out_file.close()
    if sym_file:
        sym_file.close()

    with open('symbols_out.txt', 'w') as f:
        for k, v in disassembler.symbols.items():
            f.write('{:06X}: {}\n'.format(k, v))
