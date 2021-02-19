#include "pch.h"
#include "assembler.h"

std::string Assembler::push(Register reg) {
	if (reg <= Register::RDI) {
		std::string code = { (char)(0x50 + (int)reg) };
		return code;
	}
	else {
		std::string code = { 0x41, (char)(0x50 + (int)reg - (int)Register::R8) };
		return code;
	}
}

std::string Assembler::pop(Register reg) {
	if (reg <= Register::RDI) {
		std::string code = { (char)(0x58 + (int)reg) };
		return code;
	}
	else {
		std::string code = { 0x41, (char)(0x58 + (int)reg - (int)Register::R8) };
		return code;
	}
}

std::string Assembler::pushs(Register regs[], int len) {
	std::string ret = "";
	for (int i(0); i < len; i++) {
		Register reg = regs[i];
		std::string pushCode = Assembler::push(reg);
		ret.append(pushCode);
	}
	return ret;
}

std::string Assembler::pops(Register regs[], int len) {
	std::string ret = "";
	for (int i(0); i < len; i++) {
		Register reg = regs[i];
		std::string popCode = Assembler::pop(reg);
		ret.append(popCode);
	}
	return ret;
}

std::string Assembler::addChar(Register reg, char val) {
	if (reg <= Register::RDI) {
		std::string code = { 0x48, (char)0x83, (char)(0xc0+(int)reg), val };
		return code;
	}
	else {
		std::string code = { 0x49, (char)0x83, (char)(0xc0 + (int)reg - (int)Register::R8), val };
		return code;
	}
}

std::string Assembler::subChar(Register reg, char val) {
	if (reg <= Register::RDI) {
		std::string code = { 0x48, (char)0x83, (char)(0xe8 + (int)reg), val };
		return code;
	}
	else {
		std::string code = { 0x49, (char)0x83, (char)(0xe8 + (int)reg - (int)Register::R8), val };
		return code;
	}
}

std::string Assembler::addInt(Register reg, int val) {
	char valArr[sizeof(int)];
	std::memcpy(valArr, &val, sizeof(int));
	if (reg <= Register::RDI) {
		std::string code = { 0x48, (char)0x81, (char)(0xc0 + (int)reg), valArr[0], valArr[1], valArr[2], valArr[3] };
		return code;
	}
	else {
		std::string code = { 0x49, (char)0x81, (char)(0xc0 + (int)reg - (int)Register::R8), valArr[0], valArr[1], valArr[2], valArr[3] };
		return code;
	}
}

std::string Assembler::subInt(Register reg, int val) {
	char valArr[sizeof(int)];
	std::memcpy(valArr, &val, sizeof(int));
	if (reg <= Register::RDI) {
		std::string code = { 0x48, (char)0x81, (char)(0xe8 + (int)reg), valArr[0], valArr[1], valArr[2], valArr[3] };
		return code;
	}
	else {
		std::string code = { 0x49, (char)0x81, (char)(0xe8 + (int)reg - (int)Register::R8), valArr[0], valArr[1], valArr[2], valArr[3] };
		return code;
	}
}

std::string Assembler::mov(Register dest, Register src) {
	if (dest <= Register::RDI) {
		if (src <= Register::RDI) {
			std::string code = { 0x48, (char)0x89, (char)(0xc0 + (int)dest + (8 * (int)src)) };
			return code;
		}
		else {
			std::string code = { 0x4c, (char)0x89, (char)(0xc0 + (int)dest + (8 * ((int)src-(int)Register::R8))) };
			return code;
		}
	}
	else {
		if (src <= Register::RDI) {
			std::string code = { 0x49, (char)0x89, (char)(0xc0 + ((int)dest - (int)Register::R8) + (8 * (int)src)) };
			return code;
		}
		else {
			std::string code = { 0x4d, (char)0x89, (char)(0xc0 + ((int)dest - (int)Register::R8) + (8 * ((int)src - (int)Register::R8))) };
			return code;
		}
	}
}

std::string Assembler::movSrcPtr(Register dest, Register src) {
	if (dest <= Register::RDI) {
		if (src <= Register::RDI) {
			if (src != Register::RSP && src != Register::RBP) {
				std::string code = { 0x48, (char)0x8b, (char)((int)src + (8 * (int)dest)) };
				return code;
			}
			else {
				if (src == Register::RSP) {
					std::string code = { 0x48, (char)0x8b, (char)(0x4 + (8*(int)dest)), 0x24 };
					return code;
				}
				else {
					std::string code = { 0x48, (char)0x8b, (char)(0x45 + (8*(int)dest)), 0x0 };
					return code;
				}
			}
		}
		else {
			std::string code = { 0x49, (char)0x8b, (char)((int)src + (8 * ((int)dest - (int)Register::R8))) };
			return code;
		}
	}
	else {
		if (src <= Register::RDI) {
			if (src != Register::RSP && src != Register::RBP) {
				std::string code = { 0x4c, (char)0x8b, (char)((8 * ((int)dest - (int)Register::R8)) + (int)src) };
				return code;
			}
			else {
				if (src == Register::RSP) {
					std::string code = { 0x4c, (char)0x8b, (char)(0x4 + (8 * ((int)dest - (int)Register::R8))), 0x24 };
					return code;
				}
				else {
					std::string code = { 0x4c, (char)0x8b, (char)(0x45 + (8 * ((int)dest - (int)Register::R8))), 0x0 };
					return code;
				}
			}
		}
		else {
			std::string code = { 0x4d, (char)0x8b, (char)((8 * ((int)dest - (int)Register::R8)) + ((int)src - (int)Register::R8)) };
			return code;
		}
	}
}