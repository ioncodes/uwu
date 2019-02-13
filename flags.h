#ifndef FLAGS_H
#define FLAGS_H

struct Flags
{
    /*
     * CF = BIT 0
     * PF = BIT 2
     * AF = BIT 4
     * ZF = BIT 6
     * SF = BIT 7
     * TF = BIT 8
     * IF = BIT 9
     * DF = BIT 10
     * OF = BIT 11
     * */
    int CF, PF, AF, ZF, SF, TF, IF, DF, OF;
};

#endif // FLAGS_H
