#-------------------------------------------------
#
# Project created by QtCreator 2019-02-12T19:00:48
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = uwu
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

CONFIG += c++11

SOURCES += \
        main.cpp \
        mainwindow.cpp \
    vm.cpp \
    assembler.cpp

HEADERS += \
        mainwindow.h \
    vm.h \
    assembler.h \
    registers.h

FORMS += \
        mainwindow.ui

RESOURCES += qdarkstyle/style.qrc

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

win32: LIBS += -L$$PWD/../../../../Libraries/libs/x64/ -lunicorn

INCLUDEPATH += $$PWD/../../../../Libraries/include
DEPENDPATH += $$PWD/../../../../Libraries/include

win32:!win32-g++: PRE_TARGETDEPS += $$PWD/../../../../Libraries/libs/x64/unicorn.lib
else:win32-g++: PRE_TARGETDEPS += $$PWD/../../../../Libraries/libs/x64/libunicorn.a
