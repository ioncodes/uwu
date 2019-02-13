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
}

MainWindow::~MainWindow()
{
    delete vm;
    delete assembler;
    delete ui;
}

void MainWindow::on_txtRax_returnPressed()
{

}

void MainWindow::on_txtCode_returnPressed()
{
    QString code = ui->txtCode->text();
    unsigned char* assembly = assembler->Assemble(code);
    if(assembly != nullptr)
    {
        vm->Execute(assembly);
        updateRegisters();
    }
    else
    {
        qDebug("u did an oopsie.");
    }
}

void MainWindow::updateRegisters()
{
    Registers registers = vm->ReadRegisters();
    ui->txtRax->setText(QString::number(registers.rax, 16).toUpper());
    ui->txtRbx->setText(QString::number(registers.rbx, 16).toUpper());
    ui->txtRcx->setText(QString::number(registers.rcx, 16).toUpper());
    ui->txtRdx->setText(QString::number(registers.rdx, 16).toUpper());
    ui->txtR8->setText(QString::number(registers.r8, 16).toUpper());
    ui->txtR9->setText(QString::number(registers.r9, 16).toUpper());
    ui->txtR10->setText(QString::number(registers.r10, 16).toUpper());
    ui->txtR11->setText(QString::number(registers.r11, 16).toUpper());
    ui->txtR12->setText(QString::number(registers.r12, 16).toUpper());
    ui->txtR13->setText(QString::number(registers.r13, 16).toUpper());
    ui->txtR14->setText(QString::number(registers.r14, 16).toUpper());
    ui->txtR15->setText(QString::number(registers.r15, 16).toUpper());
    ui->txtRsi->setText(QString::number(registers.rsi, 16).toUpper());
    ui->txtRdi->setText(QString::number(registers.rdi, 16).toUpper());
    ui->txtRip->setText(QString::number(registers.rip, 16).toUpper());
    ui->txtRsp->setText(QString::number(registers.rsp, 16).toUpper());
    ui->txtRbp->setText(QString::number(registers.rbp, 16).toUpper());
}
