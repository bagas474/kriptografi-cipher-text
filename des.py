import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import DES
from PIL import Image, ImageTk
import os

# Fungsi untuk membuka gambar
def import_image():
    global image_path, img
    image_path = filedialog.askopenfilename(filetypes=[("Image files", "*.jpg *.png *.bmp *.enc")])
    if image_path.endswith('.enc'):
        img_label.config(text="Encrypted file selected", image='')
        img = None  # Clear the image as it's encrypted
    else:
        img = Image.open(image_path)
        img.thumbnail((300, 300))
        img = ImageTk.PhotoImage(img)
        img_label.config(image=img)

# Fungsi untuk mengenkripsi gambar
def encrypt_image():
    if not image_path or not key_entry.get():
        messagebox.showerror("Error", "Please provide both an image and a key.")
        return
    try:
        key = key_entry.get().encode('utf-8')
        if len(key) != 8:
            messagebox.showerror("Error", "Key must be exactly 8 bytes.")
            return
        # Membuka dan membaca gambar
        with open(image_path, 'rb') as f:
            image_data = f.read()
        cipher = DES.new(key, DES.MODE_ECB)
        # Mengenkripsi gambar
        encrypted_data = cipher.encrypt(pad(image_data))
        # Menyimpan gambar terenkripsi
        save_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted files", "*.enc")])
        if save_path:
            with open(save_path, 'wb') as f:
                f.write(encrypted_data)
            messagebox.showinfo("Success", "Image encrypted successfully.")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Fungsi untuk mendekripsi gambar
def decrypt_image():
    if not image_path or not key_entry.get():
        messagebox.showerror("Error", "Please provide both an encrypted file and a key.")
        return
    try:
        key = key_entry.get().encode('utf-8')
        if len(key) != 8:
            messagebox.showerror("Error", "Key must be exactly 8 bytes.")
            return
        # Membuka dan membaca file terenkripsi
        with open(image_path, 'rb') as f:
            encrypted_data = f.read()
        cipher = DES.new(key, DES.MODE_ECB)
        # Mendekripsi file
        decrypted_data = cipher.decrypt(encrypted_data)
        save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("Image files", "*.png")])
        if save_path:
            with open(save_path, 'wb') as f:
                f.write(decrypted_data)
            messagebox.showinfo("Success", "Image decrypted successfully.")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Fungsi untuk padding data agar sesuai dengan blok 8 byte
def pad(data):
    while len(data) % 8 != 0:
        data += b' '
    return data

# Setup GUI menggunakan Tkinter
root = tk.Tk()
root.title("Image Encryption and Decryption (DES)")
root.geometry("400x500")

# Label untuk menampilkan gambar yang diimpor
img_label = tk.Label(root, text="No image selected")
img_label.pack(pady=20)

# Tombol untuk impor gambar
import_button = tk.Button(root, text="Import Image/Encrypted File", command=import_image)
import_button.pack(pady=10)

# Input untuk kunci
key_label = tk.Label(root, text="Enter 8-byte Key:")
key_label.pack(pady=5)
key_entry = tk.Entry(root, show="*")
key_entry.pack(pady=5)

# Tombol untuk enkripsi dan dekripsi
encrypt_button = tk.Button(root, text="Encrypt Image", command=encrypt_image)
encrypt_button.pack(pady=10)

decrypt_button = tk.Button(root, text="Decrypt File", command=decrypt_image)
decrypt_button.pack(pady=10)

# Loop utama
root.mainloop()