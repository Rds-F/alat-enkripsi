from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import os

# === AES-256 Functions ===
def generate_aes_key():
    """Generate a secure 32-byte (256-bit) key."""
    return base64.b64encode(os.urandom(32)).decode()

def encrypt_aes256(data, key):
    """Encrypt data using AES-256."""
    key = base64.b64decode(key.encode())
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = iv + cipher.encrypt(pad(data, AES.block_size))
    return base64.b64encode(ciphertext).decode()

def decrypt_aes256(data, key):
    """Decrypt data using AES-256."""
    key = base64.b64decode(key.encode())
    ciphertext = base64.b64decode(data)
    iv, ciphertext = ciphertext[:16], ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

# === Caesar Cipher ===
def caesar_encrypt(text, shift):
    """Encrypt text using Caesar Cipher."""
    result = ''
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            result += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            result += char
    return result

def caesar_decrypt(text, shift):
    """Decrypt text using Caesar Cipher."""
    return caesar_encrypt(text, -shift)

# === XOR Cipher ===
def xor_encrypt(text, key):
    """Encrypt text using XOR Cipher."""
    return ''.join(chr(ord(c) ^ key) for c in text)

def xor_decrypt(text, key):
    """Decrypt text using XOR Cipher."""
    return xor_encrypt(text, key)

# === File Encryption/Decryption ===
def encrypt_file(file_path, key, output_path):
    """Encrypt a file using AES-256."""
    with open(file_path, 'rb') as file:
        data = file.read()
    encrypted_data = encrypt_aes256(data, key)
    with open(output_path, 'wb') as file:
        file.write(base64.b64decode(encrypted_data))
    print(f"File terenkripsi berhasil disimpan di: {output_path}")

def decrypt_file(file_path, key, output_path):
    """Decrypt a file using AES-256."""
    with open(file_path, 'rb') as file:
        data = base64.b64encode(file.read()).decode()
    decrypted_data = decrypt_aes256(data, key)
    with open(output_path, 'wb') as file:
        file.write(decrypted_data)
    print(f"File didekripsi berhasil disimpan di: {output_path}")

# === Menu Utama ===
def main():
    print("=== Aplikasi Enkripsi | BY Rds-F ===")
    print("1. Generate AES Key")
    print("2. AES-256 (Encrypt Text)")
    print("3. AES-256 (Decrypt Text)")
    print("4. AES-256 (Encrypt File)")
    print("5. AES-256 (Decrypt File)")
    print("6. Caesar Cipher (Encrypt Text) =err=")
    print("7. Caesar Cipher (Decrypt Text) =err=")
    print("8. XOR Cipher (Encrypt Text) =err=")
    print("9. XOR Cipher (Decrypt Text) =err=")
    print("0. Exit")

    while True:
        choice = input("\nPilih opsi: ")
        if choice == "1":
            key = generate_aes_key()
            print("Generated AES Key (Base64 Encoded):", key)
        elif choice == "2":
            text = input("Masukkan teks: ").encode()
            key = input("Masukkan kunci (256-bit, Base64 Encoded): ")
            try:
                encrypted = encrypt_aes256(text, key)
                print("Hasil Enkripsi (AES-256):", encrypted)
            except Exception as e:
                print("Error:", e)
        elif choice == "3":
            encrypted_text = input("Masukkan teks terenkripsi: ")
            key = input("Masukkan kunci (256-bit, Base64 Encoded): ")
            try:
                decrypted = decrypt_aes256(encrypted_text, key).decode()
                print("Hasil Dekripsi (AES-256):", decrypted)
            except Exception as e:
                print("Error:", e)
        elif choice == "4":
            file_path = input("Masukkan path file: ")
            output_path = input("Masukkan path untuk file terenkripsi: ")
            key = input("Masukkan kunci (256-bit, Base64 Encoded): ")
            try:
                encrypt_file(file_path, key, output_path)
            except Exception as e:
                print("Error:", e)
        elif choice == "5":
            file_path = input("Masukkan path file terenkripsi: ")
            output_path = input("Masukkan path untuk file dekripsi: ")
            key = input("Masukkan kunci (256-bit, Base64 Encoded): ")
            try:
                decrypt_file(file_path, key, output_path)
            except Exception as e:
                print("Error:", e)
        elif choice == "6":
            text = input("Masukkan teks: ")
            shift = int(input("Masukkan pergeseran (shift): "))
            print("Hasil Enkripsi (Caesar):", caesar_encrypt(text, shift))
        elif choice == "7":
            encrypted_text = input("Masukkan teks terenkripsi: ")
            shift = int(input("Masukkan pergeseran (shift): "))
            print("Hasil Dekripsi (Caesar):", caesar_decrypt(encrypted_text, shift))
        elif choice == "8":
            text = input("Masukkan teks: ")
            key = int(input("Masukkan kunci (angka): "))
            print("Hasil Enkripsi (XOR):", xor_encrypt(text, key))
        elif choice == "9":
            encrypted_text = input("Masukkan teks terenkripsi: ")
            key = int(input("Masukkan kunci (angka): "))
            print("Hasil Dekripsi (XOR):", xor_decrypt(encrypted_text, key))
        elif choice == "0":
            print("Terima kasih telah menggunakan aplikasi ini.")
            break
        else:
            print("Pilihan tidak valid. Coba lagi.")

if __name__ == "__main__":
    main()
