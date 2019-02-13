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
