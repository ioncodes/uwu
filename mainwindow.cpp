#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    this->setFixedSize(this->size());
    ui->txtCode->setFocus();

    vm = new VM();
    assembler = new Assembler();

    updateRegisters();
    updateFlags();
}

MainWindow::~MainWindow()
{
    delete vm;
    delete assembler;
    delete ui;
}

void MainWindow::on_txtCode_returnPressed()
{
    QString code = ui->txtCode->text();
    unsigned char* assembly = assembler->Assemble(code);
    if(assembly != nullptr)
    {
        vm->Execute(assembly);
        updateRegisters();
        updateFlags();
    }
    else
    {
        qDebug("u did an oopsie.");
    }
}

void MainWindow::updateRegisters()
{
    Registers registers = vm->ReadRegisters();
    ui->txtRax->setText(QString::number(registers.RAX, 16).toUpper());
    ui->txtRbx->setText(QString::number(registers.RBX, 16).toUpper());
    ui->txtRcx->setText(QString::number(registers.RCX, 16).toUpper());
    ui->txtRdx->setText(QString::number(registers.RDX, 16).toUpper());
    ui->txtR8->setText(QString::number(registers.R8, 16).toUpper());
    ui->txtR9->setText(QString::number(registers.R9, 16).toUpper());
    ui->txtR10->setText(QString::number(registers.R10, 16).toUpper());
    ui->txtR11->setText(QString::number(registers.R11, 16).toUpper());
    ui->txtR12->setText(QString::number(registers.R12, 16).toUpper());
    ui->txtR13->setText(QString::number(registers.R13, 16).toUpper());
    ui->txtR14->setText(QString::number(registers.R14, 16).toUpper());
    ui->txtR15->setText(QString::number(registers.R15, 16).toUpper());
    ui->txtRsi->setText(QString::number(registers.RSI, 16).toUpper());
    ui->txtRdi->setText(QString::number(registers.RDI, 16).toUpper());
    ui->txtRip->setText(QString::number(registers.RIP, 16).toUpper());
    ui->txtRsp->setText(QString::number(registers.RSP, 16).toUpper());
    ui->txtRbp->setText(QString::number(registers.RBP, 16).toUpper());
}

void MainWindow::updateFlags()
{
    Flags flags = vm->ReadFlags();
    ui->lblAF->setText(QString::number(flags.AF));
    ui->lblCF->setText(QString::number(flags.CF));
    ui->lblDF->setText(QString::number(flags.DF));
    ui->lblIF->setText(QString::number(flags.IF));
    ui->lblOF->setText(QString::number(flags.OF));
    ui->lblPF->setText(QString::number(flags.PF));
    ui->lblSF->setText(QString::number(flags.SF));
    ui->lblTF->setText(QString::number(flags.TF));
    ui->lblZF->setText(QString::number(flags.ZF));
}

void MainWindow::on_txtRax_returnPressed()
{
    int rax = ui->txtRax->text().toInt(nullptr, 16);
    vm->SetRegister(UC_X86_REG_EAX, rax);
    updateRegisters();
}

void MainWindow::on_txtRbx_returnPressed()
{
    int rbx = ui->txtRbx->text().toInt(nullptr, 16);
    vm->SetRegister(UC_X86_REG_EBX, rbx);
    updateRegisters();
}

void MainWindow::on_txtRcx_returnPressed()
{
    int rcx = ui->txtRcx->text().toInt(nullptr, 16);
    vm->SetRegister(UC_X86_REG_ECX, rcx);
    updateRegisters();
}

void MainWindow::on_txtRdx_returnPressed()
{
    int rdx = ui->txtRdx->text().toInt(nullptr, 16);
    vm->SetRegister(UC_X86_REG_EDX, rdx);
    updateRegisters();
}

void MainWindow::on_txtR8_returnPressed()
{
    int r8 = ui->txtR8->text().toInt(nullptr, 16);
    vm->SetRegister(UC_X86_REG_R8, r8);
    updateRegisters();
}

void MainWindow::on_txtR9_returnPressed()
{
    int r9 = ui->txtR9->text().toInt(nullptr, 16);
    vm->SetRegister(UC_X86_REG_R9, r9);
    updateRegisters();
}

void MainWindow::on_txtR10_returnPressed()
{
    int r10 = ui->txtR10->text().toInt(nullptr, 16);
    vm->SetRegister(UC_X86_REG_R10, r10);
    updateRegisters();
}

void MainWindow::on_txtR11_returnPressed()
{
    int r11 = ui->txtR11->text().toInt(nullptr, 16);
    vm->SetRegister(UC_X86_REG_R11, r11);
    updateRegisters();
}

void MainWindow::on_txtR12_returnPressed()
{
    int r12 = ui->txtR12->text().toInt(nullptr, 16);
    vm->SetRegister(UC_X86_REG_R12, r12);
    updateRegisters();
}

void MainWindow::on_txtR13_returnPressed()
{
    int r13 = ui->txtR13->text().toInt(nullptr, 16);
    vm->SetRegister(UC_X86_REG_R13, r13);
    updateRegisters();
}

void MainWindow::on_txtR14_returnPressed()
{
    int r14 = ui->txtR14->text().toInt(nullptr, 16);
    vm->SetRegister(UC_X86_REG_R14, r14);
    updateRegisters();
}

void MainWindow::on_txtR15_returnPressed()
{
    int r15 = ui->txtR15->text().toInt(nullptr, 16);
    vm->SetRegister(UC_X86_REG_R15, r15);
    updateRegisters();
}

void MainWindow::on_txtRsi_returnPressed()
{
    int rsi = ui->txtRsi->text().toInt(nullptr, 16);
    vm->SetRegister(UC_X86_REG_ESI, rsi);
    updateRegisters();
}

void MainWindow::on_txtRdi_returnPressed()
{
    int rdi = ui->txtRdi->text().toInt(nullptr, 16);
    vm->SetRegister(UC_X86_REG_EDI, rdi);
    updateRegisters();
}

void MainWindow::on_txtRip_returnPressed()
{
    int rip = ui->txtRip->text().toInt(nullptr, 16);
    vm->SetRegister(UC_X86_REG_EIP, rip);
    updateRegisters();
}

void MainWindow::on_txtRsp_returnPressed()
{
    int rsp = ui->txtRsp->text().toInt(nullptr, 16);
    vm->SetRegister(UC_X86_REG_ESP, rsp);
    updateRegisters();
}

void MainWindow::on_txtRbp_returnPressed()
{
    int rbp = ui->txtRbp->text().toInt(nullptr, 16);
    vm->SetRegister(UC_X86_REG_EBP, rbp);
    updateRegisters();
}
