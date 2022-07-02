from PyQt5.QtWidgets import QMainWindow, QApplication, QDialog, QFileDialog
from PyQt5 import QtWidgets
from PyQt5 import uic
import sys
import json
import Crypto_func

from pathlib import Path

# Check file exist lib
from os.path import exists as file_exists


class UI(QMainWindow):  # QMainWindow is main window
    # email = str
    # name = str
    # birth = str
    # phone_num = str
    # address = str
    # passphase = str
    def __init__(self):
        super(UI, self).__init__()
        uic.loadUi("log_in.ui", self)
        self.show()
        # Click vao button

        self.register_button.clicked.connect(self.register)
        self.log_in_button.clicked.connect(self.log_in)

    def register(self):
        # Take chu email_r_2 trong qt lam text
        email = self.email_r_2.text()
        name = self.name_r_2.text()
        birth = self.birth_r_2.text()
        phone_num = self.phonenumber_r_2.text()
        address = self.address_r_2.text()
        passphase = self.passphase_r_2.text()

        pem_pubkey, pem_prikey = Crypto_func.rsa_keygen()

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
            "passphase": Crypto_func.hash_256(passphase),
            "public_key": pem_pubkey,
            "private_key": pem_prikey
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

    def loged_in(self, email):
        print("You log in with email : ", email)
        w = UI.Func(email)
        widget.addWidget(w)
        widget.setCurrentIndex(widget.currentIndex() + 1)

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
            self.loged_in(email)
            return
        print("Wrong password")

    class Func(QDialog):  # QDialog for sub window to open from main window (See in QT designer Object Inspector)
        def __init__(self, email):
            self.email_login = email
            super(UI.Func, self).__init__()
            uic.loadUi("Functions.ui", self)
            self.show()
            self.UpdateProfile.clicked.connect(self.switch_updateinfo)
            self.Encrypt.clicked.connect(self.switch_encrypt_file)

        def switch_updateinfo(self):
            w = UI.Func.UpdateInfo(self.email_login)
            widget.addWidget(w)
            widget.setCurrentIndex(widget.currentIndex() + 1)

        def switch_encrypt_file(self):
            w = UI.Func.EncryptFile()
            widget.addWidget(w)
            widget.setCurrentIndex(widget.currentIndex() + 1)

        class UpdateInfo(QDialog):  # QDialog for sub window to open from main window
            def __init__(self, email_log_in):
                self.email_loged_in = email_log_in
                super(UI.Func.UpdateInfo, self).__init__()
                uic.loadUi("Update_info.ui", self)
                self.show()
                self.ConfirmInfo_button.clicked.connect(self.ConfirmInfo)

            def ConfirmInfo(self):  # Done
                print("Update user : ", self.email_loged_in, "\n")
                name_u = self.InputName.text()
                birth_u = self.InputDoB.text()
                phonenum_u = self.InputPhoneNum.text()
                address_u = self.InputAddress.text()
                passphrase_u = self.passphrase_change.text()

                # Split email to name.json
                json_filename = self.email_loged_in.split("@")[0]
                json_filename = json_filename + ".json"

                # Load file json to check log in
                load_open = open(json_filename)
                read_data = json.load(load_open)

                # Close file
                load_open.close()

                if name_u == "" and birth_u == "" and phonenum_u == "" and address_u == "" and passphrase_u == "":
                    return

                if name_u == "":
                    name_u = read_data['name']
                if birth_u == "":
                    birth_u = read_data['birth']
                if phonenum_u == "":
                    phonenum_u = read_data['phone_number']
                if address_u == "":
                    address_u = read_data['address']
                if passphrase_u == "":
                    passphrase_u = read_data['passphase']

                json_user_update = {
                    "email": self.email_loged_in,
                    "name": name_u,
                    "birth": birth_u,
                    "phone_number": phonenum_u,
                    "address": address_u,
                    "passphase": Crypto_func.hash_256(passphrase_u),
                    "public_key": read_data['public_key'],
                    "private_key": read_data['private_key']
                }

                # Write to json file
                json_object = json.dumps(json_user_update, indent=4)

                with open(json_filename, "w") as outfile:
                    outfile.write(json_object)
                    outfile.close()

        class EncryptFile(QDialog):  # QDialog for sub window to open from main window
            def __init__(self):
                super(UI.Func.EncryptFile, self).__init__()
                uic.loadUi("Encrypt.ui", self)
                self.show()

                self.browser_file_button.clicked.connect(self.browser_file)

            def browser_file(self):
                fname = QFileDialog.getOpenFileName(self, 'Open file')
                #  QFileDialog.getOpenFileName(self, 'Open file', path('D:\HCMUS\...'), extension( '.png', '.xml', ...))

                self.File_selected_box.setText(fname[0])


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
