#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "vm.h"
#include "assembler.h"

#include <QLineEdit>
#include <QMainWindow>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
private slots:
    void on_txtRax_returnPressed();
    void on_txtCode_returnPressed();

    void on_txtRbx_returnPressed();

    void on_txtRcx_returnPressed();

    void on_txtRdx_returnPressed();

    void on_txtR8_returnPressed();

    void on_txtR9_returnPressed();

    void on_txtR10_returnPressed();

    void on_txtR11_returnPressed();

    void on_txtR12_returnPressed();

    void on_txtR13_returnPressed();

    void on_txtR14_returnPressed();

    void on_txtR15_returnPressed();

    void on_txtRsi_returnPressed();

    void on_txtRdi_returnPressed();

    void on_txtRip_returnPressed();

    void on_txtRsp_returnPressed();

    void on_txtRbp_returnPressed();

private:
    Ui::MainWindow *ui;
    VM *vm;
    Assembler *assembler;
    void updateRegisters();
    void updateFlags();
};

#endif // MAINWINDOW_H
