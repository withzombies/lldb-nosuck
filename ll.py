#!/usr/bin/env python

import lldb
import struct
import pdb
try:
	from termcolor import colored
except:
	print "ERROR: Could not load termcolor. Please type 'sudo easy_install termcolor'"
	exit(1)

arch = 'x86'

REGISTERS = {}
REGISTERS['x86_64'] = ("rax", "rbx", "rcx", "rdx", "rdi", "rsi", "rbp", "rsp", 
						"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", 
						"rip", "rflags", "cs", "fs", "gs", "eax", "ebx", "ecx", 
						"edx", "edi", "esi", "ebp", "esp", "ax", "bx", "cx", 
						"dx", "di", "si", "bp", "sp", "ah", "bh", "ch", "dh", 
						"al", "bl", "cl", "dl", "dil", "sil", "bpl", "spl",)


# Get Address Color
def GAC(process, addr):
	global arch

	if arch == 'x86' or arch == 'arm':
		width = 4
		a = "%08x" % (addr, )
	else:
		width = 8
		a = "%016x" % (addr, )

	aa = "0x" + a
	address_bytes = [int(a[i:i+2], 16) for i in xrange(0, len(a), 2)]
	all_ascii = map(lambda x: x > 0x20 and x <= 0x7f, address_bytes)

	address_words = [int(a[i:i+4], 16) for i in xrange(0, len(a), 4)]
	all_unicode = map(lambda x: x > 0x20 and x <= 0xff, address_words)

	# Check to see if the address is all ascii values or looks unicode-ish
	if all(all_unicode) or all(all_ascii):
		return colored(aa, 'red')

	error = lldb.SBError()
	bytes_read = process.ReadMemory(addr, width, error)
	if not error.Success():
		return aa

	br = struct.unpack("B" * width, bytes_read)
	br_all_ascii = map(lambda x: x > 0x20 and x <= 0x7f, br)

	br_u = struct.unpack("H" * (width / 2), bytes_read)
	br_all_unicode = map(lambda x: x > 0x20 and x <= 0xff, br_u)

	if all(br_all_ascii) or all(br_all_unicode):
		return colored(aa, 'yellow')

	return colored(aa, 'grey')


def get_registers(frame):
	registers = frame.GetRegisters()

	gp = list(registers[0])

	rv = {}
	for i in xrange(len(gp)):
		rv[gp[i].GetName()] = int(gp[i].GetValue(), 0)

	return rv


def hook_stop(debugger, command, result, internal_dict):
	global arch, got_info

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

	if arch == 'x86_64':
		flags  = "O " if (r['rflags'] >> 0xb) & 1 else "o "
		flags += "D " if (r['rflags'] >> 0xa) & 1 else "d "
		flags += "I " if (r['rflags'] >> 0x9) & 1 else "i "
		flags += "T " if (r['rflags'] >> 0x8) & 1 else "t "
		flags += "S " if (r['rflags'] >> 0x7) & 1 else "s "
		flags += "Z " if (r['rflags'] >> 0x6) & 1 else "z "
		flags += "A " if (r['rflags'] >> 0x5) & 1 else "a "
		flags += "P " if (r['rflags'] >> 0x4) & 1 else "p "
		flags += "C " if (r['rflags'] >> 0x3) & 1 else "c "

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
	global arch, got_info

	if debugger.GetNumTargets() > 0:
		target = debugger.GetTargetAtIndex(0)
		triple = target.GetTriple()

		(arch, manufacturer, platform) = triple.split('-')

		got_info = True

def __lldb_init_module(debugger, internal_dict):
	global arch, got_info

	get_info(debugger)

	if arch == 'x86' or arch == 'x86_64':
		debugger.HandleCommand('set set target.x86-disassembly-flavor intel')

	debugger.HandleCommand('command script add -f ll.hook_stop ll_hook')
	debugger.HandleCommand('target stop-hook add --one-liner ll_hook')
	debugger.HandleCommand('set set stop-disassembly-display never')
