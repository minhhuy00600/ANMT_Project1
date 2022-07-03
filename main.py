from PyQt5.QtWidgets import QMainWindow, QApplication, QDialog, QFileDialog
from PyQt5 import QtWidgets
from PyQt5 import uic
import sys
import json
import Crypto_func
import os

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
            self.Decrypt.clicked.connect(self.switch_decrypt_file)

        def switch_updateinfo(self):
            w = UI.Func.UpdateInfo(self.email_login)
            widget.addWidget(w)
            widget.setCurrentIndex(widget.currentIndex() + 1)

        def switch_encrypt_file(self):
            w = UI.Func.EncryptFile(self.email_login)
            widget.addWidget(w)
            widget.setCurrentIndex(widget.currentIndex() + 1)

        def switch_decrypt_file(self):
            w = UI.Func.DecryptFile()
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
            def __init__(self, email_log_in):
                self.email_loged_in = email_log_in
                super(UI.Func.EncryptFile, self).__init__()
                uic.loadUi("Encrypt.ui", self)
                self.show()

                self.browser_file_button.clicked.connect(self.browser_file)

            def browser_file(self):
                fname = QFileDialog.getOpenFileName(self, 'Open file')
                #  QFileDialog.getOpenFileName(self, 'Open file', path('D:\HCMUS\...'), extension( '.png', '.xml', ...))

                self.File_selected_box.setText(fname[0])

                self.EncryptASend.clicked.connect(self.EncryptFile_exe)

            def EncryptFile_exe(self):
                path = self.File_selected_box.text()
                if not path:
                    return

                # # Split to json filename to open to take KPrivate
                # json_filename = self.email_loged_in.split("@")[0]
                # json_filename = json_filename + ".json"

                # Get current file extension ( .xml, .txt, .json, ...)
                # cur_file_ex = os.path.splitext(path)

                # Get filename
                filename_e = path.split("/")[-1]

                #  Generate Key Session AES for encrypt file
                Ksession_aes, Nonce = Crypto_func.aes_ksession()
                with open(path, 'rb') as read_bin_file:
                    file_bin = read_bin_file.read()
                read_bin_file.close()

                # Encrypt file
                file_bin_e = Crypto_func.aes_enc_file(Ksession_aes, file_bin)

                # Write encrypted file
                with open('Encrypted File/' + filename_e, 'wb') as write_bin_file:
                    write_bin_file.write(file_bin_e)
                write_bin_file.close()

                # Write session key
                with open('Encrypted File/sessionkey_' + filename_e.split(".")[0] + '.key', 'wb') as write:
                    write.write(Ksession_aes)
                write.close()

                # Write Nonce
                with open('Encrypted File/Nonce_' + filename_e.split(".")[0] + '.key', 'wb') as write_n:
                    write_n.write(Nonce)
                write_n.close()
                print("----File encrypted successfully----")
                return

        class DecryptFile(QDialog):  # QDialog for sub window to open from main window
            def __init__(self):
                super(UI.Func.DecryptFile, self).__init__()
                uic.loadUi("Decrypt.ui", self)
                self.show()

                self.browserfile_button.clicked.connect(self.browser_file)

            def browser_file(self):
                filename = QFileDialog.getOpenFileName(self, 'Open file')
                #  QFileDialog.getOpenFileName(self, 'Open file', path('D:\HCMUS\...'), extension( '.png', '.xml', ...))

                self.File_selected_box_d.setText(filename[0])

                self.DecryptASend.clicked.connect(self.DecryptFile_exe)

            def DecryptFile_exe(self):
                path = self.File_selected_box_d.text()

                with open(path, 'rb') as read_bin_file:
                    file_to_de = read_bin_file.read()
                read_bin_file.close()
                file_name_to_d = path.split("/")[-1]

                # Read session key
                with open('Encrypted File/sessionkey_' + file_name_to_d.split(".")[0] + '.key', 'rb') as read_ks:
                    key_session = read_ks.read()
                read_ks.close()

                # Read Nonce
                with open('Encrypted File/Nonce_' + file_name_to_d.split(".")[0] + '.key', 'rb') as read_n:
                    Nonce = read_n.read()
                read_n.close()

                # Decryption
                file_de = Crypto_func.aes_dec(file_to_de, key_session, Nonce)
                # Write decrypted file
                with open('Decrypted File/' + file_name_to_d, 'wb') as write_file:
                    write_file.write(file_de)
                write_file.close()
                print("----Your file is decrypted----")
                return


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
