import tkinter as tk
from tkinter import filedialog, messagebox
import numpy as np

# Fungsi untuk Vigenere Cipher
def vigenere_enkripsi(plaintext, kunci):
    kunci = kunci.upper()
    cipher = ''
    panjang_kunci = len(kunci)

    for i, huruf in enumerate(plaintext):
        if huruf.isalpha():
            geser = ord(kunci[i % panjang_kunci]) - ord('A')
            if huruf.islower():
                cipher += chr((ord(huruf) - ord('a') + geser) % 26 + ord('a'))
            else: 
                cipher += chr((ord(huruf) - ord('A') + geser) % 26 + ord('A'))
        else:
            cipher += huruf
    return cipher

def vigenere_dekripsi(ciphertext, kunci):
    kunci = kunci.upper()
    plaintext = ''
    panjang_kunci = len(kunci)

    for i, huruf in enumerate(ciphertext):
        if huruf.isalpha():
            geser = ord(kunci[i % panjang_kunci]) - ord('A')
            if huruf.islower():
                plaintext += chr((ord(huruf) - ord('a') - geser) % 26 + ord('a'))
            else:
                plaintext += chr((ord(huruf) - ord('A') - geser) % 26 + ord('A'))
        else: 
            plaintext += huruf
    return plaintext

# Fungsi untuk Playfair Cipher
def buat_matriks_kunci_playfair(kunci):
    kunci = kunci.upper().replace('J', 'I')
    matriks = []
    seen = set()

    for char in kunci:
        if char not in seen and char.isalpha():
            seen.add(char)
            matriks.append(char)

    for char in 'ABCDEFGHIKLMNOPQRSTUVWXYZ':
        if char not in seen:
            matriks.append(char)

    return [matriks[i:i+5] for i in range(0, 25, 5)]

def pasangan_playfair(plaintext):
    plaintext = plaintext.upper().replace('J', 'I')
    plaintext = ''.join([char for char in plaintext if char.isalpha()])
    
    pasangan = []
    i = 0
    while i < len(plaintext):
        if i + 1 < len(plaintext) and plaintext[i] != plaintext[i + 1]:
            pasangan.append(plaintext[i:i+2])
            i += 2
        else:
            pasangan.append(plaintext[i] + 'X')
            i += 1

    return pasangan

def cari_koordinat(matriks, char):
    for row in range(5):
        for col in range(5):
            if matriks[row][col] == char:
                return row, col
    return None

def playfair_enkripsi(plaintext, kunci):
    matriks = buat_matriks_kunci_playfair(kunci)
    pasangan = pasangan_playfair(plaintext)
    cipher = ""

    for (a, b) in pasangan:
        row_a, col_a = cari_koordinat(matriks, a)
        row_b, col_b = cari_koordinat(matriks, b)

        if row_a == row_b:
            cipher += matriks[row_a][(col_a + 1) % 5]
            cipher += matriks[row_b][(col_b + 1) % 5]
        elif col_a == col_b:
            cipher += matriks[(row_a + 1) % 5][col_a]
            cipher += matriks[(row_b + 1) % 5][col_b]
        else:
            cipher += matriks[row_a][col_b]
            cipher += matriks[row_b][col_a]

    return cipher

def playfair_dekripsi(ciphertext, kunci):
    matriks = buat_matriks_kunci_playfair(kunci)
    pasangan = pasangan_playfair(ciphertext)
    plaintext = ""

    for (a, b) in pasangan:
        row_a, col_a = cari_koordinat(matriks, a)
        row_b, col_b = cari_koordinat(matriks, b)

        if row_a == row_b:
            plaintext += matriks[row_a][(col_a - 1) % 5]
            plaintext += matriks[row_b][(col_b - 1) % 5]
        elif col_a == col_b:
            plaintext += matriks[(row_a - 1) % 5][col_a]
            plaintext += matriks[(row_b - 1) % 5][col_b]
        else:
            plaintext += matriks[row_a][col_b]
            plaintext += matriks[row_b][col_a]

    return plaintext

# Fungsi untuk Hill Cipher
def buat_matriks_kunci_hill(kunci):
    if len(kunci) != 4:
        raise ValueError("Kunci harus memiliki panjang 4 untuk matriks 2x2.")

    kunci = [ord(char) - ord('A') for char in kunci.upper()]
    return np.array(kunci).reshape(2, 2)

def invers_matriks_2x2(matriks):
    determinan = int(np.round(np.linalg.det(matriks)))
    if determinan == 0:
        raise ValueError("Matriks tidak memiliki invers.")
    
    determinan_inv = pow(determinan, -1, 26)  # Mod 26
    matriks_inv = np.array([[matriks[1, 1], -matriks[0, 1]], 
                            [-matriks[1, 0], matriks[0, 0]]]) % 26
    return (determinan_inv * matriks_inv) % 26

def hill_enkripsi(plaintext, kunci):
    matriks_kunci = buat_matriks_kunci_hill(kunci)
    plaintext = plaintext.upper().replace(' ', '')
    
    if len(plaintext) % 2 != 0:
        plaintext += 'X'
    
    cipher = ""
    for i in range(0, len(plaintext), 2):
        pasangan = [ord(plaintext[i]) - ord('A'), ord(plaintext[i+1]) - ord('A')]
        hasil = np.dot(matriks_kunci, pasangan) % 26
        cipher += chr(hasil[0] + ord('A')) + chr(hasil[1] + ord('A'))

    return cipher

def hill_dekripsi(ciphertext, kunci):
    matriks_kunci = buat_matriks_kunci_hill(kunci)
    matriks_kunci_inv = invers_matriks_2x2(matriks_kunci)
    
    plaintext = ""
    for i in range(0, len(ciphertext), 2):
        pasangan = [ord(ciphertext[i]) - ord('A'), ord(ciphertext[i+1]) - ord('A')]
        hasil = np.dot(matriks_kunci_inv, pasangan) % 26
        plaintext += chr(int(hasil[0]) + ord('A')) + chr(int(hasil[1]) + ord('A'))

    return plaintext

# Fungsi Import File
def import_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if file_path:
        try:
            with open(file_path, 'r') as file:
                content = file.read()
                input_text.delete("1.0", "end")
                input_text.insert("end", content)
        except Exception as e:
            messagebox.showerror("Error", f"Gagal membaca file: {e}")

# Fungsi Enkripsi/Dekripsi
def pesan_terenkripsi():
    pesan = input_text.get("1.0", 'end-1c')
    kunci = kunci_entry.get()
    
    if len(kunci) < 12:
        messagebox.showerror("Error", "Kunci harus lebih dari 12 karakter")
        return

    if algoritma.get() == "Vigenere":
        hasil = vigenere_enkripsi(pesan, kunci)
    elif algoritma.get() == "Playfair":
        hasil = playfair_enkripsi(pesan, kunci)
    elif algoritma.get() == "Hill":
        hasil = hill_enkripsi(pesan, kunci)

    output_text.delete("1.0", "end")
    output_text.insert("end", hasil)

def pesan_terdekripsi():
    pesan = input_text.get("1.0", 'end-1c')
    kunci = kunci_entry.get()

    if len(kunci) < 4:
        messagebox.showerror("Error", "Kunci harus lebih dari 4 karakter")
        return

    if algoritma.get() == "Vigenere":
        hasil = vigenere_dekripsi(pesan, kunci)
    elif algoritma.get() == "Playfair":
        hasil = playfair_dekripsi(pesan, kunci)
    elif algoritma.get() == "Hill":
        hasil = hill_dekripsi(pesan, kunci)

    output_text.delete("1.0", "end")
    output_text.insert("end", hasil)

# GUI
root = tk.Tk()
root.title("Cipher Encryption/Decryption")

algoritma = tk.StringVar(value="Vigenere")

tk.Label(root, text="Algoritma").pack()
tk.Radiobutton(root, text="Vigenere", variable=algoritma, value="Vigenere").pack()
tk.Radiobutton(root, text="Playfair", variable=algoritma, value="Playfair").pack()
tk.Radiobutton(root, text="Hill", variable=algoritma, value="Hill").pack()

tk.Label(root, text="Pesan").pack()
input_text = tk.Text(root, height=5)
input_text.pack()

tk.Label(root, text="Kunci").pack()
kunci_entry = tk.Entry(root)
kunci_entry.pack()

tk.Button(root, text="Enkripsi", command=pesan_terenkripsi).pack()
tk.Button(root, text="Dekripsi", command=pesan_terdekripsi).pack()

tk.Label(root, text="Hasil").pack()
output_text = tk.Text(root, height=5)
output_text.pack()

# Tombol untuk import file
tk.Button(root, text="Import File", command=import_file).pack()

root.mainloop()