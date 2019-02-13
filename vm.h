#ifndef VM_H
#define VM_H

#include "registers.h"
#include "unicorn/unicorn.h"
#include "flags.h"


class VM
{
public:
    VM();
    void Execute(unsigned char *code);
    Registers ReadRegisters();
    Flags ReadFlags();
    void SetRegister(int reg, int value);
private:
    uc_engine *m_uc;
    uint64_t m_rip = 0;
};

#endif // VM_H
