from PyQt5.QtWidgets import QMainWindow, QApplication, QPushButton, QTextEdit, QDialog
from PyQt5 import QtWidgets
from PyQt5 import uic
import sys
import json
import Crypto_func

from pathlib import Path

# Check file exist lib
from os.path import exists as file_exists


class UI(QMainWindow):  # QMainWindow is main window
    def __init__(self):
        super(UI, self).__init__()
        uic.loadUi("log_in.ui", self)
        self.show()
        # Click vao button

        self.register_button.clicked.connect(self.register)
        self.log_in_button.clicked.connect(self.log_in)

        # find the widgets in the xml file
    def register(self):
        # Take chu email_r_2 trong qt lam text
        email = self.email_r_2.text()
        name = self.name_r_2.text()
        birth = self.birth_r_2.text()
        phone_num = self.phonenumber_r_2.text()
        address = self.address_r_2.text()
        passphase = self.passphase_r_2.text()
        if not email or not passphase:
            print("Email or Passphase is empty")
            return

        # Json type
        json_user = {
            "email": email,
            "name": name,
            "birth": birth,
            "phone_number": phone_num,
            "address": address,
            "passphase": Crypto_func.hash_256(passphase)
        }

        # Write to json file
        json_object = json.dumps(json_user, indent=4)

        # Writing to name.json
        json_filename = email.split("@")[0]
        json_filename = json_filename + ".json"

        # Check file exist
        check_file = './' + json_filename
        is_file = Path(check_file).is_file()

        if not is_file:
            with open(json_filename, "w") as outfile:
                outfile.write(json_object)
                outfile.close()
                print("Successfully Register\n")
        if is_file:
            print("Username exist\n")

    def log_in(self):
        # Take account detail
        email = self.email_l_2.text()
        passphrase = self.passphase_l_2.text()

        # Split to json filename
        json_filename = email.split("@")[0]
        json_filename = json_filename + ".json"

        # Load file json to check log in
        log_in_open = open(json_filename)
        data = json.load(log_in_open)

        # Close file
        log_in_open.close()
        # Check email and passphrase to let user log in

        if email == data['email'] and Crypto_func.hash_256(passphrase) == data['passphase']:
            print("Log in successfully\n")
            w = Func()
            widget.addWidget(w)
            widget.setCurrentIndex(widget.currentIndex()+1)
            return
        print("Wrong password or Email")


class Func(QDialog):  # QDialog for sub window to open from main window
    def __init__(self):
        super(Func, self).__init__()
        uic.loadUi("Functions.ui", self)
        self.show()

        # Click which button


class UpdateInfo(QDialog):  # QDialog for sub window to open from main window
    def __init__(self):
        super(UpdateInfo, self).__init__()
        uic.loadUi("Update Infomations.ui", self)
        self.show()


class EncryptFile(QDialog):  # QDialog for sub window to open from main window
    def __init__(self):
        super(EncryptFile, self).__init__()
        uic.loadUi("Encrypt.ui", self)
        self.show()


class DecryptFile(QDialog):  # QDialog for sub window to open from main window
    def __init__(self):
        super(DecryptFile, self).__init__()
        uic.loadUi("Decrypt.ui", self)
        self.show()


class Sign(QDialog):  # QDialog for sub window to open from main window
    def __init__(self):
        super(Sign, self).__init__()
        uic.loadUi("Sign.ui", self)
        self.show()


class ConfirmSign(QDialog):
    def __init__(self):
        super(ConfirmSign, self).__init__()
        uic.loadUi("ConfirmSign.ui", self)
        self.show()


app = QApplication(sys.argv)
window = UI()
widget = QtWidgets.QStackedWidget()
widget.addWidget(window)

widget.setFixedWidth(800)
widget.setFixedHeight(380)
widget.show()

app.exec_()


# if __name__ == '__main__':
#     main()
