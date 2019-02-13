#ifndef VM_H
#define VM_H

#include "registers.h"
#include "unicorn/unicorn.h"


class VM
{
public:
    VM();
    void Execute(unsigned char *code);
    Registers ReadRegisters();
private:
    uc_engine *m_uc;
    uint64_t m_rip = 0;
};

#endif // VM_H
