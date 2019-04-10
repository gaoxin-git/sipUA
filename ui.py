# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'ui.ui'
#
# Created by: PyQt5 UI code generator 5.11.2
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.resize(320, 240)
        self.uaName = QtWidgets.QLineEdit(Dialog)
        self.uaName.setGeometry(QtCore.QRect(0, 0, 113, 20))
        self.uaName.setObjectName("uaName")
        self.pushButtonReg = QtWidgets.QPushButton(Dialog)
        self.pushButtonReg.setGeometry(QtCore.QRect(120, 0, 75, 23))
        self.pushButtonReg.setObjectName("pushButtonReg")
        self.pushButtonUnreg = QtWidgets.QPushButton(Dialog)
        self.pushButtonUnreg.setGeometry(QtCore.QRect(200, 0, 75, 23))
        self.pushButtonUnreg.setObjectName("pushButtonUnreg")
        self.callName = QtWidgets.QLineEdit(Dialog)
        self.callName.setGeometry(QtCore.QRect(0, 50, 113, 20))
        self.callName.setObjectName("callName")
        self.pushButtonCall = QtWidgets.QPushButton(Dialog)
        self.pushButtonCall.setGeometry(QtCore.QRect(120, 50, 75, 23))
        self.pushButtonCall.setObjectName("pushButtonCall")
        self.pushButtonCancelCall = QtWidgets.QPushButton(Dialog)
        self.pushButtonCancelCall.setGeometry(QtCore.QRect(200, 50, 75, 23))
        self.pushButtonCancelCall.setObjectName("pushButtonCancelCall")
        self.pushButtonAnswer = QtWidgets.QPushButton(Dialog)
        self.pushButtonAnswer.setGeometry(QtCore.QRect(120, 110, 75, 23))
        self.pushButtonAnswer.setObjectName("pushButtonAnswer")
        self.pushButtonCancel = QtWidgets.QPushButton(Dialog)
        self.pushButtonCancel.setGeometry(QtCore.QRect(200, 110, 75, 23))
        self.pushButtonCancel.setObjectName("pushButtonCancel")
        self.inCallName = QtWidgets.QLineEdit(Dialog)
        self.inCallName.setGeometry(QtCore.QRect(0, 110, 113, 20))
        self.inCallName.setReadOnly(True)
        self.inCallName.setObjectName("inCallName")

        self.retranslateUi(Dialog)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "Dialog"))
        self.pushButtonReg.setText(_translate("Dialog", "Register"))
        self.pushButtonUnreg.setText(_translate("Dialog", "unRegister"))
        self.pushButtonCall.setText(_translate("Dialog", "Call"))
        self.pushButtonCancelCall.setText(_translate("Dialog", "Cancel"))
        self.pushButtonAnswer.setText(_translate("Dialog", "Answer"))
        self.pushButtonCancel.setText(_translate("Dialog", "Cancel"))

