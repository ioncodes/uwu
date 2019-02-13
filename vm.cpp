#include "vm.h"

int getBit(int data, int bit)
{
    return (data & (1 << bit)) >> bit;
}

VM::VM()
{
    uc_open(UC_ARCH_X86, UC_MODE_64, &m_uc);
    uc_mem_map(m_uc, 0x400000, 2 * 1024 * 1024, UC_PROT_ALL);
}

void VM::Execute(unsigned char *code)
{
    uc_mem_write(m_uc, 0x400000 + m_rip, code, sizeof(code) - 1);
    uc_emu_start(m_uc, 0x400000 + m_rip, 0x400000 + m_rip + sizeof(code) - 1, 0, 0);

    m_rip += sizeof(code);
}


Flags VM::ReadFlags()
{
    int flags;
    uc_reg_read(m_uc, UC_X86_REG_EFLAGS, &flags);

    int CF = getBit(flags, 0),
        PF = getBit(flags, 2),
        AF = getBit(flags, 4),
        ZF = getBit(flags, 6),
        SF = getBit(flags, 7),
        TF = getBit(flags, 8),
        IF = getBit(flags, 9),
        DF = getBit(flags, 10),
        OF = getBit(flags, 11);

    return Flags { CF, PF, AF, ZF, SF, TF, IF, DF, OF };
}

Registers VM::ReadRegisters()
{
    int rax, rbx, rcx, rdx, r8, r9, r10, r11, r12, r13, r14, r15, rsi, rdi, rip, rsp, rbp;

    uc_reg_read(m_uc, UC_X86_REG_RAX, &rax);
    uc_reg_read(m_uc, UC_X86_REG_RBX, &rbx);
    uc_reg_read(m_uc, UC_X86_REG_RCX, &rcx);
    uc_reg_read(m_uc, UC_X86_REG_RDX, &rdx);
    uc_reg_read(m_uc, UC_X86_REG_R8, &r8);
    uc_reg_read(m_uc, UC_X86_REG_R9, &r9);
    uc_reg_read(m_uc, UC_X86_REG_R10, &r10);
    uc_reg_read(m_uc, UC_X86_REG_R11, &r11);
    uc_reg_read(m_uc, UC_X86_REG_R12, &r12);
    uc_reg_read(m_uc, UC_X86_REG_R13, &r13);
    uc_reg_read(m_uc, UC_X86_REG_R14, &r14);
    uc_reg_read(m_uc, UC_X86_REG_R15, &r15);
    uc_reg_read(m_uc, UC_X86_REG_RSI, &rsi);
    uc_reg_read(m_uc, UC_X86_REG_RDI, &rdi);
    uc_reg_read(m_uc, UC_X86_REG_RIP, &rip);
    uc_reg_read(m_uc, UC_X86_REG_RSP, &rsp);
    uc_reg_read(m_uc, UC_X86_REG_RBP, &rbp);

    return Registers { rax, rbx, rcx, rdx, r8, r9, r10, r11, r12, r13, r14, r15, rsi, rdi, rip, rsp, rbp };
}
