#include "assembler.h"

Assembler::Assembler()
{
    keystone = new QLibrary("keystone.dll");
    ks_open = reinterpret_cast<_ks_open>(keystone->resolve("ks_open"));
    ks_asm = reinterpret_cast<_ks_asm>(keystone->resolve("ks_asm"));
    ks_close = reinterpret_cast<_ks_close>(keystone->resolve("ks_close"));
    ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
}

unsigned char* Assembler::Assemble(QString code)
{
    size_t count;
    unsigned char *encode;
    size_t size;
    if(ks_asm(ks, code.toStdString().data(), 0, &encode, &size, &count) == KS_ERR_OK)
    {
        return encode;
    }
    else
    {
        return nullptr;
    }
}

Assembler::~Assembler()
{
    ks_close(ks);
    keystone->unload();
}
