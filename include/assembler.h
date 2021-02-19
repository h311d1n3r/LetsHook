#pragma once
#include <string>

enum class Register {
	RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15
};

class Assembler {
public:
	static std::string push(Register);
	static std::string pop(Register);
	static std::string pushs(Register[], int);
	static std::string pops(Register[], int);
	static std::string addChar(Register, char);
	static std::string subChar(Register, char);
	static std::string addInt(Register, int);
	static std::string subInt(Register, int);
	static std::string mov(Register, Register);
	static std::string movSrcPtr(Register, Register);
};