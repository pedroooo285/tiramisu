#tiramisu_pbkdf2_server
import os, sys, struct, paramiko, ctypes
from PyQt5.QtWidgets import (
    QApplication, QWidget, QPushButton, QLabel, QLineEdit,
    QVBoxLayout, QHBoxLayout, QFileDialog, QMessageBox, QFrame
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

class TiramisuCrypto:
    MAGIC   = b"TIRA"
    VERSION = b"\x01\x00"
    PBKDF2_ITER = 200000
    CHUNK_SIZE = 384 * 1024

    @staticmethod
    def _aad(salt, iv):
        return TiramisuCrypto.MAGIC + TiramisuCrypto.VERSION + salt + iv

    @staticmethod
    def _stream_chunks(f):
        return iter(lambda: f.read(TiramisuCrypto.CHUNK_SIZE), b"")

    @staticmethod
    def _parse_header(f):
        salt_len = struct.unpack(">I", f.read(4))[0]
        salt = f.read(salt_len)

        iv_len = struct.unpack(">I", f.read(4))[0]
        iv = f.read(iv_len)

        tag_len = struct.unpack(">I", f.read(4))[0]
        return salt, iv, tag_len

    @staticmethod
    def _build_header(salt, iv):
        return (
            TiramisuCrypto.MAGIC +
            TiramisuCrypto.VERSION +
            struct.pack(">I", len(salt)) + salt +
            struct.pack(">I", len(iv)) + iv +
            struct.pack(">I", 16)  # panjang tag GCM
        )

    @staticmethod
    def derive_key(password: bytes, salt: bytes) -> bytes:
        return PBKDF2(password, salt, dkLen=32, count=TiramisuCrypto.PBKDF2_ITER)

    @staticmethod
    def encrypt_file(input_file, password, auto_delete=True):
        try:
            if not input_file or not os.path.isfile(input_file):
                return None

            salt = get_random_bytes(16)
            iv   = get_random_bytes(12)
            key  = TiramisuCrypto.derive_key(password.encode(), salt)

            out = input_file + ".tira"
            tmp = out + ".tmp"

            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            cipher.update(TiramisuCrypto._aad(salt, iv))

            header = TiramisuCrypto._build_header(salt, iv)

            with open(input_file, "rb") as fin, open(tmp, "wb") as fout:
                fout.write(header)

                for chunk in TiramisuCrypto._stream_chunks(fin):
                    fout.write(cipher.encrypt(chunk))

                tag = cipher.digest()
                fout.write(tag)

            os.replace(tmp, out)
            if auto_delete:
                os.remove(input_file)

            return out
        except:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except:
                pass
            return None

    @staticmethod
    def decrypt_file(input_file, password, auto_delete=True):
        try:
            if not input_file or not os.path.isfile(input_file):
                return None

            with open(input_file, "rb") as fin:
                if fin.read(4) != TiramisuCrypto.MAGIC:
                    return None
                if fin.read(2) != TiramisuCrypto.VERSION:
                    return None

                salt, iv, _ = TiramisuCrypto._parse_header(fin)
                header_size = fin.tell()

                key = TiramisuCrypto.derive_key(password.encode(), salt)

                fin.seek(-16, os.SEEK_END)
                tag = fin.read(16)

                cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
                cipher.update(TiramisuCrypto._aad(salt, iv))

                file_size = os.path.getsize(input_file)
                ciphertext_len = file_size - header_size - 16

                fin.seek(header_size)

                out = input_file[:-5] if input_file.endswith(".tira") else input_file + ".dec"

                with open(out, "wb") as fout:
                    remaining = ciphertext_len
                    while remaining > 0:
                        chunk = fin.read(min(TiramisuCrypto.CHUNK_SIZE, remaining))
                        if not chunk:
                            break
                        fout.write(cipher.decrypt(chunk))
                        remaining -= len(chunk)

                cipher.verify(tag)

            if auto_delete:
                os.remove(input_file)

            return out
        except:
            return None

class TiramisuGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)
        self.setStyleSheet("""
            QWidget { background:#1e1e1e; color:#e8e8e8; font-family:'Segoe UI'; font-size:12pt; }
            QLabel { color:#f0f0f0; }
            QLineEdit {
                background:#2a2a2a; border:1px solid #3b3b3b;
                padding:10px; border-radius:10px; color:white;
            }
            QLineEdit:focus { border:2px solid #9D4EDD; background:#262626; }
            QPushButton {
                background:#2d2d2d; color:white; padding:10px;
                border-radius:10px; border:1px solid #3d3d3d; font-weight:bold;
            }
            QPushButton:hover { border:2px solid #9D4EDD; background:#34224a; }
            QPushButton:pressed { border:2px solid #5A189A; background:#1b1026; }
        """)

        self.setGeometry(450, 200, 400, 400)
        self.setWindowTitle("Tiramisu - File Encryption")

        self.title = QLabel("Tiramisu")
        font = QFont("Segoe UI", 22, QFont.Bold)
        self.title.setFont(font)
        self.title.setAlignment(Qt.AlignCenter)

        self.subtitle = QLabel("Powered by AES-256-GCM + PBKDF2")
        self.subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.subtitle.setStyleSheet("color:#9D4EDD;font-size:9pt;font-style:italic;")

        self.file_input = QLineEdit()
        self.file_input.setPlaceholderText("Drag & drop file atau klik Browse")

        self.pass_input = QLineEdit()
        self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.pass_input.setPlaceholderText("Masukkan password...")
        self.pass_input.textChanged.connect(self.update_strength)

        self.eye_btn = QPushButton("●●●")
        self.eye_btn.setFixedWidth(60)
        self.eye_btn.clicked.connect(self.toggle_password)

        self.bars = [QFrame() for _ in range(4)]
        for b in self.bars:
            b.setFixedHeight(4)
            b.setStyleSheet("background:#333;border-radius:2px;")

        strength = QHBoxLayout()
        strength.setSpacing(6)
        for b in self.bars:
            strength.addWidget(b)

        pass_layout = QHBoxLayout()
        pass_layout.addWidget(self.pass_input)
        pass_layout.addWidget(self.eye_btn)

        browse = QPushButton("Browse")
        browse.clicked.connect(self.browse_file)

        bck = QPushButton("Backup File")
        bck.clicked.connect(self.backup_action)

        enc = QPushButton("Encrypt")
        enc.clicked.connect(self.encrypt_action)

        dec = QPushButton("Decrypt")
        dec.clicked.connect(self.decrypt_action)

        file_layout = QHBoxLayout()
        file_layout.addWidget(self.file_input)
        file_layout.addWidget(browse)
        
        btns = QHBoxLayout()
        btns.addWidget(enc)
        btns.addWidget(dec)

        layout = QVBoxLayout(self)
        layout.addWidget(self.title)
        layout.addWidget(self.subtitle)
        layout.addWidget(QLabel("File:"))
        layout.addLayout(file_layout)
        layout.addWidget(QLabel("Password:"))
        layout.addLayout(pass_layout)
        layout.addLayout(strength)
        layout.addWidget(QLabel("Action:")) 
        layout.addWidget(bck) 
        layout.addLayout(btns)
        layout.setSpacing(14)
        layout.setContentsMargins(30, 20, 30, 20)

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e):
        self.file_input.setText(e.mimeData().urls()[0].toLocalFile())

    def update_strength(self, t):
        colors = ["#333"] * 4
        if len(t) > 0: colors[0] = "#ff3b3b"
        if len(t) > 7: colors[:2] = ["#f5c542"] * 2
        if len(t) > 13: colors[:3] = ["#4cd964"] * 3
        if len(t) > 20: colors = ["#9D4EDD"] * 4
        for b, c in zip(self.bars, colors):
            b.setStyleSheet(f"background:{c};border-radius:2px;")

    def toggle_password(self):
        show = self.pass_input.echoMode() == QLineEdit.EchoMode.Password
        self.pass_input.setEchoMode(
            QLineEdit.EchoMode.Normal if show else QLineEdit.EchoMode.Password
        )
        self.eye_btn.setText("abc" if show else "●●●")

    def browse_file(self):
        p, _ = QFileDialog.getOpenFileName(self, "Pilih File")
        if p: self.file_input.setText(p)

    def _run_crypto(self, func, ok, fail):
        out = func(self.file_input.text(), self.pass_input.text(), True)
        QMessageBox.information(self, "Success", f"{ok}\n{out}") if out \
            else QMessageBox.critical(self, "Error", fail)
        if out:
            self.file_input.clear()

    def backup_action(self):
        local_path = self.file_input.text().strip()
        if not local_path or not os.path.isfile(local_path):
            QMessageBox.critical(self, "Error", "File belum dipilih atau path tidak valid.")
            return

        try:
            host = "127.0.1.1"
            port = 22
            username = "kali"
            password = "kali"
            remote_dir = "/home/kali/backup"
            filename = os.path.basename(local_path)
            remote_path = f"{remote_dir}/{filename}"

            # SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # auto-accept fingerprint
            ssh.connect(hostname=host, port=port, username=username, password=password)

            # SFTP upload
            sftp = ssh.open_sftp()
            sftp.put(local_path, remote_path)
            sftp.close()
            ssh.close()

            QMessageBox.information(
                self,
                "Success",
                f"Backup berhasil!\n{remote_path}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Backup Failed", str(e))

    def encrypt_action(self):
        self._run_crypto(
            TiramisuCrypto.encrypt_file,
            "Enkripsi berhasil!",
            "Enkripsi gagal!"
        )

    def decrypt_action(self):
        self._run_crypto(
            TiramisuCrypto.decrypt_file,
            "Dekripsi berhasil!",
            "Dekripsi gagal!"
        )

if __name__ == "__main__":
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    window = TiramisuGUI()
    window.show()

    sys.exit(app.exec_())
