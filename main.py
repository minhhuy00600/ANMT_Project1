from PyQt5.QtWidgets import QMainWindow, QApplication, QPushButton, QTextEdit
from PyQt5 import QtWidgets
from PyQt5 import uic
import sys
import json
import Crypto_func

from pathlib import Path

# Check file exist lib
from os.path import exists as file_exists


class UI(QMainWindow):
    def __init__(self):
        super(UI, self).__init__()
        uic.loadUi("log_in.ui", self)
        self.show()
        # Click vao button

        self.register_button.clicked.connect(self.register)

        # find the widgets in the xml file
    def register(self):
        # Take chu email_r_2 trong qt lam text
        email = self.email_r_2.text()
        name = self.name_r_2.text()
        birth = self.birth_r_2.text()
        phone_num = self.phonenumber_r_2.text()
        address = self.address_r_2.text()
        passphase = self.passphase_r_2.text()

        # Json type
        json_user = {
            "email": email,
            "name": name,
            "birth": birth,
            "phone_number": phone_num,
            "address": address,
            "passphase": passphase
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


def main():
    app = QApplication(sys.argv)
    window = UI()
    app.exec_()


if __name__ == '__main__':
    main()