from tkinter import *
from tkinter import filedialog, simpledialog, messagebox
import tkinter as tk 
from tkinter import ttk
from PIL import Image, ImageTk
import os 
import base64
import secrets
from stegano import lsb
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import hashlib

# Create appliction window
root = Tk()
root.title("Steganography - Hide a Secret Text Message in an Image")
root.geometry("700x500+150+180")
root.resizable(False,False)
root.configure(bg = "#2f4155")


# Create a key for encryption 
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Updated derive_key function to support SHA512
def derive_key(password, salt=None, hash_algorithm="SHA256"):
    if salt is None:
        salt = secrets.token_bytes(16)
    
    password_provided = password
    password = password_provided.encode()

    # Print out selected hashing algorithm for confirmation
    # print(f"Selected Hashing Algorithm: {hash_algorithm}")
    
    # Choose the hashing algorithm based on user selection
    if hash_algorithm == "SHA256":
        print("Initiating SHA256 hashing for key derivation...")
        algorithm = hashes.SHA256()
    elif hash_algorithm == "SHA512":
        print("Initiating SHA512 hashing for key derivation...")
        algorithm = hashes.SHA512()
    else:
        raise ValueError(f"Unsupported hashing algorithm: {hash_algorithm}")

    kdf = PBKDF2HMAC(
        algorithm=algorithm,
        iterations=100000,
        salt=salt,
        length=32  # Length of the derived key
    )

    key = kdf.derive(password)
    return key, salt

# Fernet encryption
def fernet_encrypt(message, key):
    # Convert the derived key to a 32-byte Fernet-compatible key
    fernet_key = base64.urlsafe_b64encode(key[:32])  # Ensure key is 32 bytes for Fernet
    cipher_suite = Fernet(fernet_key)
    encrypted_message = cipher_suite.encrypt(message)
    return encrypted_message.decode('utf-8')  # Return Base64 encoded result as string

# Fernet decryption
def fernet_decrypt(encrypted_message, key):
    # Reconstruct the Fernet key using the derived key
    fernet_key = base64.urlsafe_b64encode(key[:32])  # Fernet keys must be 32 bytes, base64 encoded
    cipher_suite = Fernet(fernet_key)
    
    try:
        decrypted_message = cipher_suite.decrypt(encrypted_message.encode())
        return decrypted_message
    except InvalidToken:
        print("Invalid token - decryption failed.")
        return None

# AES Encryption
def aes_encrypt(message, key):
    iv = secrets.token_bytes(16)  # AES block size is 16 bytes
    print("IV (Generated during encryption):", iv)

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padded_message = pad_message(message)
    print("Padded Message (Before Encryption):", padded_message)

    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    print("Encrypted Message (Before Base64):", iv + encrypted_message)

    # Concatenate IV and encrypted_message, then Base64 encode
    base64_encoded_message = base64.b64encode(iv + encrypted_message).decode('utf-8')  # Return Base64-encoded string
    print("Encrypted Message (Base64 Encoded):", base64_encoded_message)

    return base64_encoded_message

# Enhanced AES Decryption
def aes_decrypt(encrypted_message, key):
    try:
        # Decode Base64 encoded message
        encrypted_message = base64.b64decode(encrypted_message)
        print("Full Encrypted Message (Decoded from Base64):", encrypted_message)

        # Extract IV
        iv = encrypted_message[:16]
        print("IV (Extracted during decryption):", iv)

        # Separate out ciphertext
        ciphertext = encrypted_message[16:]
        print("Ciphertext (Extracted during decryption):", ciphertext)

        # Decrypt using IV and derived key
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
        print("Decrypted Message Before Unpadding:", decrypted_message)

        # Unpad the decrypted message, handle padding errors if they arise
        try:
            unpadded_message = unpad_message(decrypted_message)
            print("Unpadded Decrypted Message:", unpadded_message)
            return unpadded_message
        except ValueError as e:
            print(f"Unpadding Error: {e}")
            return None
    except Exception as e:
        print(f"Decryption Exception: {e}")
        return None

# Padding and unpadding functions (no changes needed)
def pad_message(message):
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    return padder.update(message) + padder.finalize()

# Ensure proper handling of padding during decryption
def unpad_message(padded_message):
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    try:
        return unpadder.update(padded_message) + unpadder.finalize()
    except ValueError as e:
        print(f"Padding Error: {e}")
        return None


# Generate RSA keys
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt(message, public_key):
    encrypted_message = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message

def rsa_decrypt(encrypted_message, private_key):
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message

# Save RSA keys to files
def save_rsa_keys(private_key, public_key):
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("private_key.pem", "wb") as private_file:
        private_file.write(pem_private_key)
    with open("public_key.pem", "wb") as public_file:
        public_file.write(pem_public_key)

# Load RSA keys from files
def load_rsa_keys():
    with open("private_key.pem", "rb") as private_file:
        private_key = serialization.load_pem_private_key(
            private_file.read(),
            password=None,
            backend=default_backend()
        )
    with open("public_key.pem", "rb") as public_file:
        public_key = serialization.load_pem_public_key(
            public_file.read(),
            backend=default_backend()
        )
    return private_key, public_key

# Updated encrypt function to handle both AES and Fernet and to support SHA512 hashing
def encrypt(message, password, encryption_algorithm, hash_algorithm="SHA256"):
    key, salt = derive_key(password, hash_algorithm=hash_algorithm)  # Pass selected hash algorithm
    print(f"Selected Encryption Algorithm for Encryption: {encryption_algorithm}")
    print("Encryption Salt:", salt)
    print("Derived Key (Encryption):", key)

    if encryption_algorithm == "AES":
        encrypted_message = aes_encrypt(salt + message, key)
    elif encryption_algorithm == "Fernet":
        encrypted_message = fernet_encrypt(message, key)
    else:
        raise ValueError(f"Unsupported encryption algorithm: {encryption_algorithm}")

    return encrypted_message, salt

# Updated decrypt function to handle both Fernet and AES correctly based on user choice, and to support SHA512 hashing
def decrypt(encrypted_message, password, salt, encryption_algorithm, hash_algorithm="SHA256"):
    # Derive the decryption key
    key, _ = derive_key(password, salt, hash_algorithm=hash_algorithm,)
    print(f"Decryption Salt: {salt}")
    print(f"Derived Key (Decryption): {key}")
    print(f"Selected Encryption Algorithm for Decryption: {encryption_algorithm}")

    # Initialize decrypted_message_bytes to None
    decrypted_message_bytes = None

    # Clearer conditional handling based on encryption_algorithm
    if encryption_algorithm == "AES":
        print("Attempting AES decryption...")
        decrypted_message_bytes = aes_decrypt(encrypted_message, key)
    elif encryption_algorithm == "Fernet":
        print("Attempting Fernet decryption...")
        decrypted_message_bytes = fernet_decrypt(encrypted_message, key)
    else:
        print(f"Unsupported decryption algorithm selected: {encryption_algorithm}")
        return None

    # If decryption failed, log and return None
    if decrypted_message_bytes is None:
        print(f"{encryption_algorithm} decryption failed.")
        return None

    # If AES, remove the salt from the decrypted message
    if encryption_algorithm == "AES" and len(decrypted_message_bytes) > len(salt):
        decrypted_message_bytes = decrypted_message_bytes[len(salt):]
        print("Decrypted Message (After Removing Salt):", decrypted_message_bytes)

    # Convert decrypted bytes to a UTF-8 string if possible
    try:
        return decrypted_message_bytes.decode('utf-8')
    except UnicodeDecodeError:
        print("Failed to decode decrypted message to UTF-8.")
        return None

# Function to decrypt a hashed message
def decrypt_hashed_message(hashed_message, password, salt):
    derive_key = derive_key(password, salt)[0]
    cipher_suite = Fernet(derive_key)

    try:
        decrypted_message_bytes = cipher_suite.decrypt(hashed_message)
        return decrypted_message_bytes
    except InvalidToken:
        print("Invalid token - decryption failed.")
        return None


def save_key(filename, key):
    with open(filename, 'wb') as file:
        file.write(key.encode())

def read_key(filename):
    with open(filename, 'rb') as file:
        return file.read().decode()
    
# Save data (encrypted message) to file (as a string)
def save_to_file(data, filename):
    with open(filename, 'w') as file:
        file.write(data)
    print(f"Encrypted message saved to {filename}: {data}")

# Read data (encrypted message) from file
def read_from_file(filename):
    with open(filename, 'r') as file:
        content = file.read()  # Return the Base64-encoded string
    print(f"Encrypted message read from {filename}: {content}")
    return content

# Save salt (Base64-encoded) to file
def save_salt(filename, salt):
    with open(filename, 'w') as file:
        file.write(base64.b64encode(salt).decode('utf-8'))  # Save salt as Base64-encoded string

# Read and print decoded salt for debugging
def read_salt(filename):
    with open(filename, 'r') as file:
        decoded_salt = base64.b64decode(file.read())
        print("Decoded Salt (after Base64):", decoded_salt)
        return decoded_salt
    
# Function for concealing using LSB
def conceal_lsb(image_path, message):
    print("Using LSB concealment algorithm to hide the message...")  # Add this line
    return lsb.hide(image_path, message)

# Function for revealing message using LSB
def reveal_lsb(image_path):
    print("Using LSB concealment algorithm to reveal the message...")  # Add this line
    return lsb.reveal(image_path)

# LSBSet concealment placeholder with a confirmation message
def conceal_lsbset(image_path, message):
    print("Using LSBSet concealment algorithm to hide the message...")
    # Placeholder: You’ll need to use the actual LSBSet concealment function here.
    # Replace with the proper method if available.
    return lsb.hide(image_path, message)  # Example using LSB as a placeholder

# LSBSet reveal placeholder with a confirmation message
def reveal_lsbset(image_path):
    print("Using LSBSet concealment algorithm to reveal the message...")
    # Placeholder: You’ll need to use the actual LSBSet reveal function here.
    # Replace with the proper method if available.
    return lsb.reveal(image_path)  # Example using LSB as a placeholder

def conceal_stegano(image_path, message):
    # Using Stegano's LSB method
    return lsb.hide(image_path, message)

def reveal_stegano(image_path):
    # Using Stegano's LSB method
    return lsb.reveal(image_path)

  
#icon
image_icon = PhotoImage(file = "logo_icon.png")
root.iconphoto(False,image_icon)

# Home Page
def home_page():
    page = Frame(root, bg="#2f4155")
    page.place(x=0, y=0, relwidth=1, relheight=1)

    # Title
    label = Label(page, text="Welcome to the Steganography App", bg="#2f4155", fg="white", font="arial 20 bold")
    label.pack(pady=20)      

    # Instructions
    instructions = Label(page, text="This app allows you to hide and reveal secret messages in images. \n The purpose of this application is safely encode and decode the images. \n The features of this application are as follows: - \n 1. To encode and decode the images. \n 2. To secure it with passwords. ", bg="#2f4155", fg="white", font="arial 10")
    instructions.pack(pady=10)

    # Image or Logo
    logo_img = PhotoImage(file="logo_icon.png")
    logo_label = Label(page, image=logo_img, bg="#2f4155")
    logo_label.image = logo_img
    logo_label.pack(pady=20)

    # Additional Information or Tips
    tips_label = Label(page, text="Tip: You can use this app to send hidden messages securely.", bg="#2f4155", fg="white", font="arial 12 italic")
    tips_label.pack(pady=10)

# Updated get_user_info function with multiple selections
def get_user_info():
    user_info = {}

    def submit():
        user_info["concealment"] = concealment_var.get()
        user_info["encryption"] = encryption_var.get()  # Save user's selection here
        user_info["hash"] = hash_var.get()
        user_info["password"] = simpledialog.askstring("Password", "Set your password:", show='*')

        # Confirm selected hashing algorithm
        print(f"Selected Hashing Algorithm: {user_info['hash']}")  # Add this line

        if user_info["password"]:
            user_info_window.destroy()
        else:
            messagebox.showerror("Input Error", "Please set a password.")

    def cancel():
        user_info_window.destroy()

    user_info_window = Toplevel(root)
    user_info_window.title("Algorithm Selection")
    user_info_window.geometry("400x300")
    user_info_window.configure(bg="#2f4155")

    concealment_var = StringVar(value="LSB")
    encryption_var = StringVar(value="Fernet")   # Remove default, so user must select
    hash_var = StringVar(value="SHA256")

    Label(user_info_window, text="Select concealment algorithm:", bg="#2f4155", fg="white", font="arial 12").grid(row=0, column=0, pady=5, padx=10, sticky=W)
    #ttk.Combobox(user_info_window, textvariable=concealment_var, values=["LSB", "LSBSet", "ExifHeader"], state="readonly").grid(row=0, column=1, pady=5, padx=10)
    ttk.Combobox(user_info_window, textvariable=concealment_var, values=["LSB", "LSBSet"], state="readonly").grid(row=0, column=1, pady=5, padx=10)

    Label(user_info_window, text="Select encryption algorithm:", bg="#2f4155", fg="white", font="arial 12").grid(row=1, column=0, pady=5, padx=10, sticky=W)
    #ttk.Combobox(user_info_window, textvariable=encryption_var, values=["Fernet", "AES", "RSA"], state="readonly").grid(row=1, column=1, pady=5, padx=10)
    ttk.Combobox(user_info_window, textvariable=encryption_var, values=["Fernet", "AES"], state="readonly").grid(row=1, column=1, pady=5, padx=10)

    Label(user_info_window, text="Select hash algorithm:", bg="#2f4155", fg="white", font="arial 12").grid(row=2, column=0, pady=5, padx=10, sticky=W)
    #ttk.Combobox(user_info_window, textvariable=hash_var, values=["SHA256", "SHA512", "MD5"], state="readonly").grid(row=2, column=1, pady=5, padx=10)
    ttk.Combobox(user_info_window, textvariable=hash_var, values=["SHA256", "SHA512"], state="readonly").grid(row=2, column=1, pady=5, padx=10)

    submit_button = Button(user_info_window, text="Continue", command=submit, bg="white", fg="black", font="arial 12")
    submit_button.grid(row=3, column=0, pady=20, padx=10, sticky=E)

    cancel_button = Button(user_info_window, text="Cancel", command=cancel, bg="white", fg="black", font="arial 12")
    cancel_button.grid(row=3, column=1, pady=20, padx=10, sticky=W)

    user_info_window.wait_window()

    if user_info:
        return user_info["concealment"], user_info["encryption"], user_info["hash"], user_info["password"]
    else:
        return None, None, None, None


# Hide and Show
def hide_show():
    page = Frame(root, bg="#2f4155")
    page.place(x=0, y=0, relwidth=1, relheight=1)

    Label(root, text="CYBER SCIENCE", bg="#2f4155", fg="white", font="arial 25 bold").place(x=15, y=20)

    concealment_algorithms = ["LSB", "LSBSet", "ExifHeader"]
    encryption_algorithms = ["Fernet", "AES", "RSA"]
    hashing_algorithms = ["SHA256", "SHA512", "MD5"]

    global concealment_algorithm_var, encryption_algorithm_var, hash_algorithm_var, secret
    concealment_algorithm_var = StringVar(value=concealment_algorithms[0])
    encryption_algorithm_var = StringVar(value=encryption_algorithms[0])
    hash_algorithm_var = StringVar(value=hashing_algorithms[0])

    secret = None  # Initialize secret as None

    #def test_encryption_decryption():
    # This is the message and password for the test
        #message = b"THIS IS A TEST !!!"
        #password = "testpassword"

    # Test Encryption
        #print("=== TESTING ENCRYPTION ===")
        #encrypted_message, salt = encrypt(message, password, "AES")
        #print("Encrypted Message (Base64):", encrypted_message)

    # Test Decryption
        #print("=== TESTING DECRYPTION ===")
        #decrypted_message = decrypt(encrypted_message, password, salt, "AES")

        #if decrypted_message:
            # Remove the first 16 bytes (salt) from the decrypted message
            #original_message = decrypted_message[16:]
            #print("Decrypted Message (After Removing Salt):", original_message.decode('utf-8'))
        #else:
            #print("Decryption failed.")

    def showimage():
        global filename
        filename = filedialog.askopenfilename(initialdir=os.getcwd(), title='Select Image File', filetype=(("PNG file", "*.png"), ("JPG file", "*.jpg"), ("All file", "*.txt")))

        img = Image.open(filename)
        img = ImageTk.PhotoImage(img)
        lbl.configure(image=img, width=250, height=250)
        lbl.image = img

    # Hide Function: Only Encrypt and Conceal
    def Hide(concealment_algorithm, encryption_algorithm, hash_algorithm, password):
        global secret, selected_encryption_algorithm, selected_hash_algorithm
        selected_encryption_algorithm = encryption_algorithm  # Store the selected algorithm for later use
        selected_hash_algorithm = hash_algorithm  # Store the selected hash algorithm for later use
        message = text1.get(1.0, END).encode('utf-8')  # Ensure the message is byte-encoded
        encrypted_message, salt = encrypt(message, password, encryption_algorithm, hash_algorithm=hash_algorithm)

        # Save salt to file
        save_salt("salt.txt", salt)

        # Save Base64-encoded encrypted message to file as a string
        save_to_file(encrypted_message, "encrypted_message.txt")
        print("Encrypted Message (Base64 Encoded):", encrypted_message)

        # Conceal encrypted message
        if concealment_algorithm == "LSB":
            secret = conceal_lsb(filename, encrypted_message)
        elif concealment_algorithm == "LSBSet":
            secret = conceal_lsbset(filename, encrypted_message)
        elif concealment_algorithm == "ExifHeader":
            secret = conceal_lsb(filename, encrypted_message)

        print("Message concealed successfully.")
            

    # Show Function: Only Reveal and Decrypt
    def Show():
        password = simpledialog.askstring("Password", "Enter the password:", show='*')
        
        try:
            stegano_result = lsb.reveal(filename)
            if not stegano_result:
                messagebox.showerror("Error", "No hidden data found in the image.")
                return

            # Read and confirm salt and encrypted message
            salt = read_salt("salt.txt")
            encrypted_message = read_from_file("encrypted_message.txt")
            
            # Verify encryption algorithm
            encryption_algorithm = selected_encryption_algorithm  # Use the algorithm chosen in Hide
            print(f"User Selected Decryption Algorithm: {encryption_algorithm}")
            print(f"Encrypted Message (to decrypt): {encrypted_message}")

            # Derive decryption key based on provided password and salt
            derived_key, _ = derive_key(password, salt, hash_algorithm=selected_hash_algorithm)  # Use selected hash algorithm
            print("Decryption Salt:", salt)
            print("Derived Key (Decryption):", derived_key)
            print("Using selected Hash Algorithm:", selected_hash_algorithm)

            # Perform the decryption based on selected algorithm
            if encryption_algorithm == "AES":
                print("Attempting AES decryption...")
                decrypted_message_bytes = aes_decrypt(encrypted_message, derived_key)
                if decrypted_message_bytes is not None:
                    # Remove salt after successful decryption if AES is used
                    decrypted_message_bytes = decrypted_message_bytes[len(salt):]
            elif encryption_algorithm == "Fernet":
                print("Attempting Fernet decryption...")
                decrypted_message_bytes = fernet_decrypt(encrypted_message, derived_key)
            else:
                messagebox.showerror("Error", f"Unsupported algorithm selected: {encryption_algorithm}")
                return

            if decrypted_message_bytes is None:
                messagebox.showerror("Error", f"Decryption failed using {encryption_algorithm}. Check your password or encryption settings.")
                return

            try:
                decrypted_message = decrypted_message_bytes.decode('utf-8')
                print("Final Decrypted Message (Decoded):", decrypted_message)
                text1.delete(1.0, END)
                text1.insert(END, decrypted_message)
            except UnicodeDecodeError:
                messagebox.showerror("Error", "Failed to decode decrypted message.")

        except Exception as e:
            print(f"Exception during decryption: {e}")
            messagebox.showerror("Error", f"An error occurred during decryption: {str(e)}")

    def save():
        try:
            if secret:
                save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
                if save_path:
                    secret.save(save_path)
                    messagebox.showinfo("Success", "Image saved successfully.")
            else:
                messagebox.showerror("Error", "No image to save. Please hide data first.")
        except NameError:
            messagebox.showerror("Error", "No image to save. Please hide data first.")

# Add a test button to run the encryption/decryption test
    #Button(page, text="Test Encrypt/Decrypt", width=20, height=2, font="arial 14 bold", command=test_encryption_decryption).place(x=180, y=300)
    #test_encryption_decryption()
            

#######################################################
    

#######################################################
 # Frames for the Hide/Show page 

    #first frame 
    f = Frame(root,bd = 3, bg = "black", width = 340, height = 280, relief = GROOVE)
    f.place(x = 10, y = 80)

    lbl = Label(f, bg = "black")
    lbl.place(x = 40, y = 10)

    #Second Frame 
    frame2 = Frame(root, bd = 3, width = 340, height = 280, bg = "white", relief = GROOVE)
    frame2.place(x = 350, y = 80)

    text1 = Text(frame2, font = "Robote 20", bg = "white", fg = "black", relief = GROOVE, wrap = WORD)
    text1.place(x = 0, y = 0, width = 320, height = 295)

    scrollbar1 = Scrollbar(frame2)
    scrollbar1.place(x = 320, y = 0, height = 300)

    scrollbar1.configure(command = text1.yview)
    text1.configure(yscrollcommand = scrollbar1.set)

    #third frame
    frame3 = Frame(root, bd = 3, bg = "#2f4155", width = 330, height = 100, relief = GROOVE)
    frame3.place(x = 10, y = 370)

    Button(frame3, text = "Open Image", width = 10, height = 2, font = "arial 14 bold", command = showimage).place(x = 20, y = 30)
    Button(frame3, text = "Save Image", width = 10, height = 2, font = "arial 14 bold", command = save).place(x = 180, y = 30)
    Label(frame3, text = "Picture, Image, Photo File", bg = "#2f4155", fg = "yellow").place(x = 20, y = 5)

    #fourth frame
    frame4 = Frame(root, bd = 3, bg = "#2f4155", width = 330, height = 100, relief = GROOVE)
    frame4.place(x = 360, y = 370)

    Button(frame4, text="Hide Data", width=10, height=2, font="arial 14 bold", command=lambda: Hide(*get_user_info())).place(x=20, y=30)
    Button(frame4, text="Show Data", width=10, height=2, font="arial 14 bold", command=Show).place(x=180, y=30)
    Label(frame4, text = "Picture, Image, Photo File", bg = "#2f4155", fg = "yellow").place(x = 20, y = 5)

#######################################################
# About Page
def about_page():
    page = Frame(root, bg="#2f4155")
    page.place(x=0, y=0, relwidth=1, relheight=1)

    # Title
    label = Label(page, text="About Us", bg="#2f4155", fg="white", font="arial 20 bold")
    label.pack(pady=20)

    # Description
    description = Label(page, text="Steganography Application, version 1.01.01 \n Copyright(C) 2023 Crypotography Foundation \n Licensed under GNU GPL License, Version 1 \n\n E-mail: crypotograpghyfoundation@gmail.com \n Website: https://steganographyapplication.ak.net \n\n We are a team of developers passionate about cybersecurity and digital privacy.", bg="#2f4155", fg="white", font="arial 10")
    description.pack(pady=10)

    # Team Members
    members_label = Label(page, text="Team Members:", bg="#2f4155", fg="white", font="arial 16 bold")
    members_label.pack(pady=10)

    # List of Team Members
    team_members = [
        "Darijan Zumarvic - Developer",
        "Simranpreet Kaur - Developer",
    ]

    for member in team_members:
        member_label = Label(page, text=member, bg="#2f4155", fg="white", font="arial 12")
        member_label.pack()
#######################################################

# Switch to the Home Page by default
home_page()

# Menu
menu = Menu(root)
root.config(menu=menu)
menu.add_command(label="Home", command=home_page)
menu.add_command(label="Hide/Show", command=hide_show)
menu.add_command(label="About Us", command=about_page)




root.mainloop()



