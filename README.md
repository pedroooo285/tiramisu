# Tiramisu🍰
Tiramisu: Advanced File Encryption using AES-256 GCM and PBKDF2.

Tiramisu PBKDF2 adalah aplikasi enkripsi file lokal berbasis AES-256-GCM dengan PBKDF2 sebagai derivasi key dari password. Dibuat untuk Project Based Learning (PBL) dengan fokus keamanan dasar + praktik nyata.

Fitur utama:
1. Enkripsi file dengan AES-256-GCM
2. Password → Key via PBKDF2 (200.000 iterasi)
3. Proteksi integritas (file diubah → decrypt gagal)
4. GUI sederhana (PyQt5)
5. Backup file ke server via SSH (SFTP)

Alur sigkat:
1. Pilih / drag file
2. Masukkan password
3. Klik Encrypt → file jadi .tira
4. Klik Decrypt untuk mengembalikan
5. (Opsional) Backup File ke server Linux

Kebutuhan:
pip install pyqt5 pycryptodome paramiko pyinstaller

Build ke EXR (Windows):
pyinstaller --onefile --windowed tiramisu_server.py

Catatan penggunaan:
1. Password minimal 12–14 karakter
2. Salah password → decrypt gagal total
3. Cocok untuk edukasi & demonstrasi kriptografi
4. Bukan pengganti software keamanan profesional

Tujuan PBL:
1. Memahami alur enkripsi file
2. Implementasi AES-GCM + PBKDF2
3. Praktik integritas data & secure file handling
4. Simulasi backup aman via SSH
