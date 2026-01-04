# Tiramisu

**Tiramisu** adalah aplikasi enkripsi file lokal yang mengimplementasikan **AES-256-GCM** dengan **PBKDF2** sebagai mekanisme derivasi key dari password.  
Proyek ini dibuat untuk **Project Based Learning (PBL)** dengan tujuan menggabungkan konsep kriptografi dasar dan praktik keamanan dunia nyata.

---

## Deskripsi Singkat

Tiramisu mengenkripsi file secara lokal menggunakan password pengguna.  
Password tidak digunakan langsung, tetapi diproses melalui **PBKDF2 (Password-Based Key Derivation Function 2)** dengan iterasi tinggi untuk menghasilkan key kriptografi yang kuat.

Mode **AES-GCM (Galois/Counter Mode)** memastikan:
- Kerahasiaan data
- Autentikasi
- Integritas file

Jika file diubah sekecil apa pun, proses dekripsi akan gagal.

---

## Fitur Utama

- Enkripsi file menggunakan **AES-256-GCM**
- Derivasi key dari password via **PBKDF2 (200.000 iterasi)**
- Proteksi integritas otomatis (tamper detection)
- Antarmuka GUI sederhana berbasis **PyQt5**
- Backup file terenkripsi ke server Linux via **SSH (SFTP)**

---

## Alur Penggunaan

1. Pilih atau drag & drop file
2. Masukkan password
3. Klik **Encrypt** → file berubah menjadi `.tira`
4. Klik **Decrypt** untuk mengembalikan file
5. (Opsional) Backup file terenkripsi ke server

---

## Kebutuhan Sistem

Install dependensi:
```bash
pip install pyqt5 pycryptodome paramiko pyinstaller
