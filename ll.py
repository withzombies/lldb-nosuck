#!/usr/bin/env python

import lldb
import struct
import pdb
try:
	from termcolor import colored
except:
	print "ERROR: Could not load termcolor. Please type 'sudo easy_install termcolor'"
	exit(1)

got_info = False
g_arch = 'x86'
g_width = 4

REGISTERS = {}
REGISTERS['x86_64'] = ("rax", "rbx", "rcx", "rdx", "rdi", "rsi", "rbp", "rsp", 
						"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", 
						"rip", "rflags", "cs", "fs", "gs", "eax", "ebx", "ecx", 
						"edx", "edi", "esi", "ebp", "esp", "ax", "bx", "cx", 
						"dx", "di", "si", "bp", "sp", "ah", "bh", "ch", "dh", 
						"al", "bl", "cl", "dl", "dil", "sil", "bpl", "spl",)


# Get Address Color
def GAC(p, addr):
	global g_width

	def read_memory(p, addr, width=4):
		error = lldb.SBError()
		bytes_read = p.ReadMemory(addr, width, error)

		if error.Success():
			return bytes_read

		return None

	def is_value_null(addr):
		return addr == 0

	def is_value_all_ascii(addr_string):
		address_bytes = [int(addr_string[i:i+2], 16) for i in xrange(0, len(addr_string), 2)]
		return all(map(lambda x: x >= 0x20 and x <= 0x7f, address_bytes))

	def is_value_unicode_le(addr_string):
		address_bytes = [int(addr_string[i:i+4], 16) for i in xrange(0, len(addr_string), 4)]
		return all(map(lambda x: x >= 0x20 and x <= 0xff, address_bytes))

	def is_value_unicode_be(addr_string):
		address_bytes = [int(addr_string[i+2:i+4] + addr_string[i:i+2], 16) for i in xrange(0, len(addr_string), 4)]
		return all(map(lambda x: x >= 0x20 and x <= 0xff, address_bytes))

	def does_addr_point_to_ascii(p, addr, width=4):
		rv = read_memory(p, addr, width)
		if rv is None:
			return False

		bytes_array = [ord(x) for x in rv]
		return all(map(lambda x: x >= 0x20 and x <= 0x7f, bytes_array))

	def does_addr_point_to_unicode_le(p, addr, width=4):
		rv = read_memory(p, addr, width)
		if rv is None:
			return False

		word_array = struct.unpack("<" + "H" * (width / 2), rv)
		return all(map(lambda x: x >= 0x20 and x <= 0xff, word_array))

	def does_addr_point_to_unicode_be(p, addr, width=4):
		rv = read_memory(p, addr, width)
		if rv is None:
			return False

		word_array = struct.unpack(">" + "H" * (width / 2), rv)
		return all(map(lambda x: x >= 0x20 and x <= 0xff, word_array))

	def does_addr_point_to_dynamic_memory(p, addr, width=4):
		rv = read_memory(p, addr, width)
		if rv is None:
			return False

		debugger = p.target.debugger
		ci = debugger.GetCommandInterpreter()
		res = lldb.SBCommandReturnObject()
		ci.HandleCommand("image list -a 0x%x" % (addr, ), res)

		return not res.Succeeded()

	def does_addr_point_to_mapped_memory(p, addr, width=4):
		rv = read_memory(p, addr, width)
		if rv is None:
			return False

		return True

	if g_width == 4:
		addr_string = "%08x" % (addr, )
		display_address = "0x%08x" % (addr, )
	else:
		addr_string = "%016x" % (addr, )
		display_address = "0x%016x" % (addr, )

	if is_value_null(addr):
		return display_address

	if is_value_all_ascii(addr_string) or is_value_unicode_le(addr_string) or is_value_unicode_be(addr_string):
		return colored(display_address, 'red')

	if does_addr_point_to_ascii(p, addr, g_width) or does_addr_point_to_unicode_le(p, addr, g_width) or \
			does_addr_point_to_unicode_be(p, addr, g_width):
		return colored(display_address, 'yellow')

	if does_addr_point_to_dynamic_memory(p, addr, g_width):
		return colored(display_address, 'green')

	if does_addr_point_to_mapped_memory(p, addr, g_width):
		return colored(display_address, 'grey')

	return colored(display_address, 'cyan')

def get_registers(frame):
	registers = frame.GetRegisters()

	gp = list(registers[0])

	rv = {}
	for i in xrange(len(gp)):
		rv[gp[i].GetName()] = int(gp[i].GetValue(), 0)

	return rv

def dump_memory(debugger, width, command):
	global g_arch, got_info

	if debugger.GetNumTargets() == 0:
		return

	if not got_info:
		get_info(debugger)

		if not got_info:
			raise Exception("Nothing running?")

	target = debugger.GetTargetAtIndex(0)
	process = target.process

	if '--help' == command:
		print "db/dw/dd/dq [start address] [bytes to display]"
		return

	commands = command.split(' ')
	if len(commands) == 2:
		bytes_to_display = int(commands[1], 16)
		start_address = int(commands[0], 16)
	elif len(commands) == 1:
		bytes_to_display = 0x80
		start_address = int(commands[0], 16)
	else:
		print "db/dw/dd/dq [start address] [bytes to display]"
		return

	data = []
	ascii_bytes = []

	if width == 1: 
		width_fmt = "B"
		data_fmt = "0x%02x"
	elif width == 2: 
		width_fmt = "H"
		data_fmt = "0x%04x"
	elif width == 4: 
		width_fmt = "I"
		data_fmt = "0x%08x"
	elif width == 8: 
		width_fmt = "L"
		data_fmt = "0x%016x"

	error = lldb.SBError()
	for i in xrange(0, bytes_to_display, width):
		words_read = process.ReadMemory(start_address + i, width, error)
		if error.Fail():
			break
		data.append(struct.unpack(width_fmt, words_read)[0])

	out = ""
	ascii_line = ""

	i = 0
	for x in data:
		if width == g_width:
			out += GAC(process, x)
		else:
			out += data_fmt % (x, )

		ascii_word = data_fmt[2:] % (x, )
		for x in ascii_word.decode('hex')[::-1]:
			if ord(x) >= ord(' ') and ord(x) <= ord('z'):
				ascii_line += x
			else:
				ascii_line += '.'

		i += width
		out += ' '

		if i == 0x10:
			i = 0

			out += '   '
			out += ascii_line
			out += '\n'

			ascii_line = ""

	print out
		
	if error.Fail():
		print "ERROR: Address not mapped"
	

	return

def dump_memory1(debugger, command, result, internal_dict):
	return dump_memory(debugger, 1, command)

def dump_memory2(debugger, command, result, internal_dict):
	return dump_memory(debugger, 2, command)

def dump_memory4(debugger, command, result, internal_dict):
	return dump_memory(debugger, 4, command)

def dump_memory8(debugger, command, result, internal_dict):
	return dump_memory(debugger, 8, command)

def hook_stop(debugger, command, result, internal_dict):
	global g_arch, got_info

	if debugger.GetNumTargets() == 0:
		return

	if not got_info:
		get_info(debugger)

		if not got_info:
			raise Exception("Nothing running?")

	target = debugger.GetTargetAtIndex(0)
	process = target.process
	p = process
	state = process.GetState()

	thread = process.GetThreadAtIndex(0)
	frame = thread.GetFrameAtIndex(0)

	r = get_registers(frame)

	if g_arch == 'x86_64':
		flags  = colored("O ", 'cyan') if (r['rflags'] >> 0xb) & 1 else "o "
		flags += colored("D ", 'cyan') if (r['rflags'] >> 0xa) & 1 else "d "
		flags += colored("I ", 'cyan') if (r['rflags'] >> 0x9) & 1 else "i "
		flags += colored("T ", 'cyan') if (r['rflags'] >> 0x8) & 1 else "t "
		flags += colored("S ", 'cyan') if (r['rflags'] >> 0x7) & 1 else "s "
		flags += colored("Z ", 'cyan') if (r['rflags'] >> 0x6) & 1 else "z "
		flags += colored("A ", 'cyan') if (r['rflags'] >> 0x5) & 1 else "a "
		flags += colored("P ", 'cyan') if (r['rflags'] >> 0x4) & 1 else "p "
		flags += colored("C ", 'cyan') if (r['rflags'] >> 0x3) & 1 else "c "

		out  = "-" * 120 + "\n"
		out += "  rax:%s  rbx:%s  rcx:%s  rdx:%s  %s\n" % (
				GAC(p, r['rax']), 
				GAC(p, r['rbx']), 
				GAC(p, r['rcx']), 
				GAC(p, r['rdx']), 
				flags, )

		out += "  rsi:%s  rdi:%s   r8:%s   r9:%s  r10:%s\n" % (
				GAC(p, r['rsi']),
				GAC(p, r['rdi']),
				GAC(p, r['r8']),
				GAC(p, r['r9']),
				GAC(p, r['r10']), )

		out += "  r11:%s  r12:%s  r13:%s  r14:%s  r15:%s\n" % (
				GAC(p, r['r11']),
				GAC(p, r['r12']),
				GAC(p, r['r13']),
				GAC(p, r['r14']),
				GAC(p, r['r15']), )

		out += "  rsp:%s  rbp:%s  rip:%s\n" % (
				GAC(p, r['rsp']), 
				GAC(p, r['rbp']), 
				GAC(p, r['rip']), )

		out += "-" * 120 + "\n"

		print
		print out

		lldb.debugger.HandleCommand('disass -s `$rip` -c 5')

def get_info(debugger):
	global g_arch, got_info, g_width

	if debugger.GetNumTargets() > 0:
		target = debugger.GetTargetAtIndex(0)
		triple = target.GetTriple()

		(g_arch, manufacturer, platform) = triple.split('-')

		if g_arch == 'x86' or g_arch == 'arm':
			g_width = 4
		elif g_arch == 'x86_64':
			g_width = 8

		got_info = True

def __lldb_init_module(debugger, internal_dict):
	global g_arch, got_info

	get_info(debugger)

	if g_arch == 'x86' or g_arch == 'x86_64':
		debugger.HandleCommand('set set target.x86-disassembly-flavor intel')

	debugger.HandleCommand('command script add -f ll.hook_stop context')
	debugger.HandleCommand('target stop-hook add --one-liner context')
	debugger.HandleCommand('set set stop-disassembly-display never')

	debugger.HandleCommand('command script add -f ll.dump_memory1 db')
	debugger.HandleCommand('command script add -f ll.dump_memory2 dw')
	debugger.HandleCommand('command script add -f ll.dump_memory4 dd')
	debugger.HandleCommand('command script add -f ll.dump_memory8 dq')
