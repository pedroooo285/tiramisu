# SECURITY.md

Dokumen ini menjelaskan tujuan keamanan, desain kriptografi, serta batasan yang disengaja pada aplikasi **Tiramisu** dalam konteks Project Based Learning (PBL).

---

## Tujuan Keamanan

Aplikasi ini dirancang untuk melindungi file dari:

- Akses tidak sah secara **offline**
- **Modifikasi data** tanpa terdeteksi
- Kesalahan pengguna seperti **password salah** atau **file rusak**

---

## Desain Kriptografi

### Algoritma Enkripsi

**AES-256-GCM**
- Menyediakan enkripsi dan autentikasi sekaligus
- Menjamin kerahasiaan dan integritas data
- Perubahan sekecil apa pun pada ciphertext akan terdeteksi

### Derivasi Key

**PBKDF2 (Password-Based Key Derivation Function 2)**
- 200.000 iterasi
- Salt acak unik untuk setiap file
- Meningkatkan resistansi terhadap brute-force offline

### Additional Authenticated Data (AAD)

Data berikut ikut diautentikasi namun tidak dienkripsi:
- MAGIC header
- VERSION
- Salt
- Initialization Vector (IV)

Perubahan pada bagian ini akan menyebabkan proses dekripsi gagal.

---

## Prinsip Keamanan Penting

- File yang bukan format `.tira` akan **ditolak**
- Password salah menghasilkan **tidak ada output sama sekali**
- Perubahan **1 byte** pada file terenkripsi menyebabkan **dekripsi gagal**
- Penulisan file dilakukan secara **atomic** (`.tmp` → replace) untuk mencegah korupsi data

---

## Batasan (Disengaja & Edukatif)

Batasan berikut diterima karena konteks pembelajaran:

- PBKDF2 lebih lemah dibanding **Argon2** terhadap serangan GPU modern
- Password lemah tetap dapat dibobol melalui brute-force
- Plaintext dapat muncul sementara di disk selama proses dekripsi
- Tidak melindungi dari malware, keylogger, atau kompromi sistem

---

## Backup Server (Catatan Keamanan)

- SSH fingerprint diterima otomatis  
  (tidak aman, namun disederhanakan untuk PBL)
- Credential ditulis langsung di dalam kode  
  (hanya untuk demonstrasi)
- **Tidak boleh digunakan di lingkungan produksi**

---

## Kesimpulan

Tiramisu dirancang sebagai media pembelajaran kriptografi praktis,  
bukan sebagai solusi keamanan tingkat industri.

Penggunaan di luar konteks edukasi dilakukan dengan risiko sendiri.
