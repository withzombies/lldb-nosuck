#!/usr/bin/env python

import lldb
import pdb

arch = 'x86'

REGISTERS = {}
REGISTERS['x86_64'] = ("rax", "rbx", "rcx", "rdx", "rdi", "rsi", "rbp", "rsp", 
						"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", 
						"rip", "rflags", "cs", "fs", "gs", "eax", "ebx", "ecx", 
						"edx", "edi", "esi", "ebp", "esp", "ax", "bx", "cx", 
						"dx", "di", "si", "bp", "sp", "ah", "bh", "ch", "dh", 
						"al", "bl", "cl", "dl", "dil", "sil", "bpl", "spl",)

def get_registers(debugger):
	target = debugger.GetTargetAtIndex(0)
	process = target.process

	state = process.GetState()
	if state == lldb.eStateStopped:
		thread = process.GetSelectedThread()
		frame = thread.GetFrameAtIndex(0)

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
	state = process.GetState()

	thread = process.GetThreadAtIndex(0)
	frame = thread.GetFrameAtIndex(0)

	r = get_registers(debugger)

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
		out += "  rax:0x%016x  rbx:0x%016x  rcx:0x%016x  rdx:0x%016x  %s\n" % (r['rax'], r['rbx'], r['rcx'], r['rdx'], flags, )
		out += "  rsi:0x%016x  rdi:0x%016x  rsp:0x%016x  rbp:0x%016x  rip:0x%016x\n" % (r['rsi'], r['rdi'], r['rsp'], r['rbp'], r['rip'], )
		out += "-" * 120 + "\n"

		print
		print out

		lldb.debugger.HandleCommand('disass -s `$rip` -c 5')

		print "%016x" % (frame.GetPC(), )

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
