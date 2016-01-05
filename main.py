#! /usr/bin/env python3
# -*- coding:utf-8 -*-
__author__ = 'yorick'

from Crypto.Cipher import AES
from PyQt4.QtGui import *
from PyQt4 import uic
import platform
from datetime import datetime as date
import logging
import random
import sys
import os


class MainWindow(QMainWindow):
    def __init__(self):
        addr = 'logs/{}{}'.format(str(date.today())[:-7], '(de<en)crypt.log')
        logging.basicConfig(filename=addr, level=logging.ERROR)
        super(QMainWindow, self).__init__()
        ui, cls = uic.loadUiType('ui/main.ui')
        del cls
        self.ui = ui()
        self.ui.setupUi(self)
        self.setWindowIcon(QIcon('ui/main.png'))
        self.ui.view_e.setCheckable(True)
        self.ui.view_e.setIcon(QIcon('ui/on.png'))
        self.ui.view_d.setCheckable(True)
        self.ui.view_d.setIcon(QIcon('ui/on.png'))
        self.ui.enc_bar.setMinimum(0)
        self.ui.dec_bar.setMinimum(0)
        self.ui.enc_bar.setValue(0)
        self.ui.dec_bar.setValue(0)
        # some variables
        self.f_dlg = QFileDialog(self)
        self.set_directory()
        self.clipboard = QApplication.clipboard()
        # connects
        self.ui.open_encrypt.clicked.connect(self.opn_f_enc)
        self.ui.open_decrypt.clicked.connect(self.opn_f_dec)
        self.ui.open_to_encrypt.clicked.connect(self.opn_f_to_enc)
        self.ui.open_to_decrypt.clicked.connect(self.opn_f_to_dec)
        self.ui.view_e.clicked.connect(self.view_pwd_e)
        self.ui.view_d.clicked.connect(self.view_pwd_d)
        self.ui.encrypt_text.clicked.connect(self.btn_encrypt_text)
        self.ui.decrypt_text.clicked.connect(self.btn_decrypt_text)
        self.ui.encrypt_file.clicked.connect(self.btn_encrypt_file)
        self.ui.decrypt_file.clicked.connect(self.btn_decrypt_file)
        self.ui.copy_enc.clicked.connect(self.copy_encrypted_text)
        self.ui.copy_dec.clicked.connect(self.copy_decrypted_text)

    def _keyget(self, s, iv) -> str:
        if len(s) < 16:
            s += '^'*(16-len(s))
            return s
        elif len(s) > 16:
            random.seed(iv)
            s = [z for z in s]
            random.shuffle(s)
            s = s[:16]
            return s
        elif len(s) == 16:
            return s

    def split_n(self, lst, n) -> list or str:
        return [lst[z:z + n] for z in range(0, len(lst), n)]

    def decrypt_text(self, pwd, txt) -> str:
        try:
            pwd = self._keyget(pwd, pwd)
            txt = txt.replace('[', '')
            txt = txt.replace(']', '')
            txt = txt.split(',')
            txt = [int(x) for x in txt]
            txt = self.split_n(txt, 16)
            txt = tuple(txt)
            prm1 = [bytes() for x in txt]
            decryptor = AES.new(pwd, AES.MODE_CBC, pwd)
            for x in txt:
                i = txt.index(x)
                for y in txt[i]:
                    prm1[i] += bytes([y])
            ret_data = bytes()
            for x in prm1:
                ret_data += decryptor.decrypt(x)
            ret_data = str(ret_data, 'utf-8')
            del txt, pwd, prm1, decryptor
            return ret_data
        except Exception as e:
            logging.error('Eror on crypt text;')
            logging.error('Eror {};'.format(e.args))

    def encrypt_text(self, pwd, txt) -> str:
        try:
            pwd = self._keyget(pwd, pwd)
            txt = [bytes(x, 'utf-8') for x in txt]
            cryptor = AES.new(pwd, AES.MODE_CBC, pwd)
            p1 = bytes()
            for x in txt:
                p1 += x
            txt = self.split_n(p1, 16)
            ex = []
            for x in txt:
                if len(x) < 16:
                    x += bytes('\t', 'utf-8')*(16-len(x))
                ex.append(cryptor.encrypt(x))
            prm1 = bytes()
            ret_data = []
            for x in ex:
                prm1 += x
            for x in prm1:
                ret_data.append(x)
            del pwd, txt, cryptor, ex, prm1
            return str(ret_data)
        except Exception as e:
            logging.error('Eror in decrypt text;')
            logging.error('Eror {};'.format(e.args))

    def encrypt_file(self, pwd, last_addr, new_addr) -> bool:
        try:
            last_addr = os.path.abspath(last_addr)
            new_addr = os.path.abspath(new_addr)
            pwd = self._keyget(pwd, pwd)
            filesize = os.stat(last_addr)[6]
            if filesize % 16 != 0:
                count = round(filesize / 16) + 1
            else:
                count = filesize / 16
            self.ui.enc_bar.setMaximum(count)
            self.ui.enc_bar.setValue(0)
            file = open(last_addr, 'rb')
            data = file.read(16)
            new_file = open(new_addr, 'wb')
            new_file.close()
            encryptor = AES.new(pwd, AES.MODE_CBC, pwd)
            i = 0
            while i < count:
                if len(data) < 16:
                    data += b'^'*(16 - len(data))
                rtd = encryptor.encrypt(data)
                new_file = open(new_addr, 'ab')
                new_file.write(rtd)
                new_file.close()
                self.ui.enc_bar.setValue(i)
                i += 1
                data = file.read(16)
            file.close()
            del last_addr, pwd, new_addr, data, file, i, encryptor, count
            return True
        except Exception as e:
            logging.error('Eror on encrypting file;')
            logging.error('File size: {};'.format(os.stat(last_addr)[6]))
            logging.error('Eror {};'.format(e.args))

    def decrypt_file(self, pwd, last_addr, new_addr) -> bool:
        try:
            last_addr = os.path.abspath(last_addr)
            new_addr = os.path.abspath(new_addr)
            pwd = self._keyget(pwd, pwd)
            filesize = os.stat(last_addr)[6]
            if filesize % 16 != 0:
                count = round(filesize / 16) + 1
            else:
                count = filesize / 16
            self.ui.dec_bar.setMaximum(count)
            self.ui.dec_bar.setValue(0)
            file = open(last_addr, 'rb')
            data = file.read(16)
            new_file = open(new_addr, 'wb')
            new_file.close()
            decryptor = AES.new(pwd, AES.MODE_CBC, pwd)
            i = 0
            while i < count:
                rtd = decryptor.decrypt(data)
                if i+1 == count:
                    while bytes([rtd[-1]]) == b'^':
                        rtd = rtd[:len(rtd)-1]
                new_file = open(new_addr, 'ab')
                new_file.write(rtd)
                new_file.close()
                self.ui.dec_bar.setValue(i)
                i += 1
                data = file.read(16)
            file.close()
            del last_addr, pwd, new_addr, data, file, i, decryptor, count
            return True
        except Exception as e:
            logging.error('Eror on decrypting file;')
            logging.error('File size {};'.format(os.stat(last_addr)[6]))
            logging.error('Eror {};'.format(e.args))

    def opn_f_enc(self) -> None:
        addr_encrypt = self.f_dlg.getOpenFileName(self, 'Open file', r'/')
        self.ui.addr_enc.setText(addr_encrypt)
        del addr_encrypt

    def opn_f_dec(self) -> None:
        addr_decrypt = self.f_dlg.getOpenFileName(self, 'Open file', r'/')
        self.ui.addr_dec.setText(addr_decrypt)
        del addr_decrypt

    def opn_f_to_enc(self) -> None:
        addr_to_encrypt = self.f_dlg.getSaveFileName(self, 'Open file', r'/')
        self.ui.addr_to_enc.setText(addr_to_encrypt)
        del addr_to_encrypt

    def opn_f_to_dec(self) -> None:
        addr_to_decrypt = self.f_dlg.getSaveFileName(self, 'Open file', r'/')
        self.ui.addr_to_dec.setText(addr_to_decrypt)
        del addr_to_decrypt

    def view_pwd_e(self) -> None:
        txt_1 = self.ui.pwd1_e.text()
        txt_2 = self.ui.pwd2_e.text()
        if self.ui.view_e.isChecked():
            self.ui.pwd1_e.setEchoMode(QLineEdit.Normal)
            self.ui.pwd2_e.setEchoMode(QLineEdit.Normal)
            self.ui.pwd1_e.setText(txt_1)
            self.ui.pwd1_e.setText(txt_2)
            self.ui.view_e.setIcon(QIcon('ui/off.png'))
        else:
            self.ui.pwd1_e.setEchoMode(QLineEdit.Password)
            self.ui.pwd2_e.setEchoMode(QLineEdit.Password)
            self.ui.pwd1_e.setText(txt_1)
            self.ui.pwd1_e.setText(txt_2)
            self.ui.view_e.setIcon(QIcon('ui/on.png'))

    def view_pwd_d(self) -> None:
        txt_1 = self.ui.pwd1_d.text()
        txt_2 = self.ui.pwd2_d.text()
        if self.ui.view_d.isChecked():
            self.ui.pwd1_d.setEchoMode(QLineEdit.Normal)
            self.ui.pwd2_d.setEchoMode(QLineEdit.Normal)
            self.ui.pwd1_d.setText(txt_1)
            self.ui.pwd1_d.setText(txt_2)
            self.ui.view_d.setIcon(QIcon('ui/off.png'))
        else:
            self.ui.pwd1_d.setEchoMode(QLineEdit.Password)
            self.ui.pwd2_d.setEchoMode(QLineEdit.Password)
            self.ui.pwd1_d.setText(txt_1)
            self.ui.pwd1_d.setText(txt_2)
            self.ui.view_d.setIcon(QIcon('ui/on.png'))

    def btn_encrypt_file(self) -> None:
        f_addr_old = self.ui.addr_enc.text()
        f_addr_new = self.ui.addr_to_enc.text()
        pwd = self.ui.pwd1_e.text()
        repwd = self.ui.pwd2_e.text()
        if pwd == repwd:
            reply = self.encrypt_file(pwd, f_addr_old, f_addr_new)
            if reply:
                QMessageBox.question(self,
                                     'Done',
                                     'Done, encrypted file is located at the address: \n{}'.format(f_addr_new),
                                     QMessageBox.Yes)
            else:
                QMessageBox.question(self,
                                     'Eror',
                                     'Eror ,failed to encrypt the file!!!',
                                     QMessageBox.Yes)
            del f_addr_new, f_addr_old, pwd, repwd, reply
        else:
            QMessageBox.question(self,
                                 'Eror',
                                 'Password is not correct!!!',
                                 QMessageBox.Yes)
            del f_addr_new, f_addr_old, pwd, repwd

    def btn_decrypt_file(self) -> None:
        f_addr_old = self.ui.addr_dec.text()
        f_addr_new = self.ui.addr_to_dec.text()
        pwd = self.ui.pwd1_d.text()
        repwd = self.ui.pwd2_d.text()
        if pwd == repwd:
            reply = self.decrypt_file(pwd, f_addr_old, f_addr_new)
            if reply:
                QMessageBox.question(self,
                                     'Done',
                                     'Done, decrypted file is located at the address: \n{}'.format(f_addr_new),
                                     QMessageBox.Yes)
            else:
                QMessageBox.question(self,
                                     'Eror',
                                     'Eror ,failed to decrypt the file!!!',
                                     QMessageBox.Yes)
            del f_addr_new, f_addr_old, pwd, repwd, reply
        else:
            QMessageBox.question(self,
                                 'Eror',
                                 'Password is not correct!!!',
                                 QMessageBox.Yes)
            del f_addr_new, f_addr_old, pwd, repwd

    def btn_encrypt_text(self) -> None:
        text_t_enc = self.ui.text_to_enc.toPlainText()
        pwd = self.ui.pwd_e.text()
        enc_txt = self.encrypt_text(pwd, text_t_enc)
        if enc_txt is not False:
            self.ui.enc_text.setText(enc_txt)
        else:
            QMessageBox.question(self,
                                 'Eror',
                                 'Eror on encrypt data!!!',
                                 QMessageBox.Yes)
        del text_t_enc, pwd, enc_txt

    def copy_encrypted_text(self):
        text = self.ui.enc_text.toPlainText()
        self.clipboard.clear()
        self.clipboard.setText(text)

    def copy_decrypted_text(self):
        text = self.ui.dec_text.toPlainText()
        self.clipboard.clear()
        self.clipboard.setText(text)

    def btn_decrypt_text(self) -> None:
        text_t_enc = self.ui.text_to_dec.toPlainText()
        pwd = self.ui.pwd_d.text()
        enc_txt = self.decrypt_text(pwd, text_t_enc)
        if enc_txt is not False:
            self.ui.dec_text.setText(enc_txt)
        else:
            QMessageBox.question(self,
                                 'Eror',
                                 'Eror on encrypt data!!!',
                                 QMessageBox.Yes)
        del text_t_enc, pwd, enc_txt

    def set_directory(self) -> None:
        system = platform.system()
        if system == 'Linux':
            self.f_dlg.setDirectory(r'/')
        elif system == 'Windows':
            self.f_dlg.setDirectory(r'C://')
        elif system == 'Java':
            self.f_dlg.setDirectory(r'')

    def closeEvent(self, event):
        l_dir = list(os.walk('logs/'))[0][2]
        d = []
        for x in l_dir:
            path = os.path.join('logs/', x)
            d.append(path)
        for x in d:
            opf = open(x, 'rt')
            txt = opf.read()
            opf.close()
            if txt == '':
                os.remove(x)
        event.accept()


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
