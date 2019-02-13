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

    void updateRegisters();
private slots:
    void on_txtRax_returnPressed();
    void on_txtCode_returnPressed();

private:
    Ui::MainWindow *ui;
    VM *vm;
    Assembler *assembler;
};

#endif // MAINWINDOW_H
