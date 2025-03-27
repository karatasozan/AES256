import tkinter as tk
from PIL import Image, ImageTk  # Pillow
from Crypto.Cipher import AES
import hashlib
import base64
from tkinter import messagebox

# Tkinter window
window = tk.Tk()
window.title("Secret Notes")
window.config(padx=30, pady=30)
window.minsize(width=300, height=500)

#Photo import
image = Image.open("topsc2.jpg")
image = image.resize((100, 100))
photo = ImageTk.PhotoImage(image)

def pad(text):
    return text + (16 - len(text) % 16) * chr(16 - len(text) % 16)

def unpad(text):
    """Şifreli metni açarken padding’i kaldırır"""
    return text[:-ord(text[-1])]

def aes_encrypt(text, password):
    """AES-256 ile metni şifreler"""
    key = hashlib.sha256(password.encode()).digest()  # 256 bit (32 byte) key oluştur
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_text = cipher.encrypt(pad(text).encode())
    return base64.b64encode(encrypted_text).decode()

#savedButton
def savedButton():
    title = title_label_input.get()
    key = master_label_input.get()
    secret_text = secret_label_input.get("1.0",tk.END)
    with open("mySecret.txt", "a", encoding="utf-8") as page:
        page.write(f"Title: {title}\n")
        page.write(f"Sifreli hali :{aes_encrypt(secret_text,key)}\n")

def aes_decrypt(encrypted_text, password):
    """AES-256 ile şifrelenmiş metni çözer"""
    key = hashlib.sha256(password.encode()).digest()  # Aynı 256 bit key oluştur
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_text = cipher.decrypt(base64.b64decode(encrypted_text)).decode()
    return unpad(decrypted_text)

#DecryptButton
def dcButton():
    secret_text = secret_label_input.get("1.0", tk.END)
    key = master_label_input.get()
    aes_decrypt(secret_text,key)
    messagebox.showinfo("Info",aes_decrypt(secret_text,key))


#ui
label = tk.Label( image=photo)
label.pack()
title_label = tk.Label(text="Enter Your Title")
title_label.pack()
title_label_input = tk.Entry(width=20)
title_label_input.pack()
secret_label = tk.Label(text="Enter Your Secret")
secret_label.pack()
secret_label_input = tk.Text(width=30, height=10)
secret_label_input.pack()
master_label = tk.Label(text="Enter Your Master Key")
master_label.pack()
master_label_input = tk.Entry(width=20)
master_label_input.pack()
saved_button = tk.Button(text="Save&Encrypt",command=savedButton)
saved_button.pack()
dc_button = tk.Button(text="Decrypt",command=dcButton)
dc_button.pack()



window.mainloop()


