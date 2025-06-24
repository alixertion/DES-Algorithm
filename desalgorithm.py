import tkinter as tk
from tkinter import messagebox, scrolledtext
import base64
import random

# --- DES Tables ---

IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

IP_INV = [40, 8, 48, 16, 56, 24, 64, 32,
          39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30,
          37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28,
          35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26,
          33, 1, 41, 9, 49, 17, 57, 25]

E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

S_BOX = [
    [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
     [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
     [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
     [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
    
    [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
     [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
     [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
     [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],

    [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
     [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
     [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
     [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],

    [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
     [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
     [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
     [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],

    [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
     [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
     [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
     [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],

    [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
     [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
     [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
     [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],

    [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
     [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
     [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
     [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],

    [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
     [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
     [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
     [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]
]

PC1 = [57,49,41,33,25,17,9,
       1,58,50,42,34,26,18,
       10,2,59,51,43,35,27,
       19,11,3,60,52,44,36,
       63,55,47,39,31,23,15,
       7,62,54,46,38,30,22,
       14,6,61,53,45,37,29,
       21,13,5,28,20,12,4]

PC2 = [14,17,11,24,1,5,3,28,15,6,
       21,10,23,19,12,4,26,8,16,7,
       27,20,13,2,41,52,31,37,47,55,
       30,40,51,45,33,48,44,49,39,56,
       34,53,46,42,50,36,29,32]

SHIFT_TABLE = [1, 1, 2, 2, 2, 2, 2, 2,
               1, 2, 2, 2, 2, 2, 2, 1]

# --- Functions ---
def permute(block, table):
    return [block[i - 1] for i in table]

def left_shift(bits, n):
    return bits[n:] + bits[:n]

def generate_keys(key_64bit):
    key_permuted = permute(key_64bit, PC1)
    C = key_permuted[:28]
    D = key_permuted[28:]
    round_keys = []
    for shift in SHIFT_TABLE:
        C = left_shift(C, shift)
        D = left_shift(D, shift)
        combined = C + D
        subkey = permute(combined, PC2)
        round_keys.append(subkey)
    return round_keys

def s_box_substitution(expanded_half_block):
    output = []
    for i in range(8):
        block = expanded_half_block[i*6:(i+1)*6]
        row = (block[0] << 1) + block[5]
        col = (block[1] << 3) + (block[2] << 2) + (block[3] << 1) + block[4]
        val = S_BOX[i][row][col]
        bits = [(val >> j) & 1 for j in reversed(range(4))]
        output.extend(bits)
    return output

def f(right_half, subkey):
    expanded_right = permute(right_half, E)
    xor_result = [bit ^ k for bit, k in zip(expanded_right, subkey)]
    sbox_output = s_box_substitution(xor_result)
    return permute(sbox_output, P)

def encrypt_block(plaintext_bits, round_keys):
    permuted_input = permute(plaintext_bits, IP)
    L = permuted_input[:32]
    R = permuted_input[32:]
    for i in range(16):
        temp_R = R.copy()
        f_output = f(R, round_keys[i])
        R = [l ^ fo for l, fo in zip(L, f_output)]
        L = temp_R
    return permute(R + L, IP_INV)

def decrypt_block(ciphertext_bits, round_keys):
    permuted_input = permute(ciphertext_bits, IP)
    L = permuted_input[:32]
    R = permuted_input[32:]
    for i in range(15, -1, -1):
        temp_R = R.copy()
        f_output = f(R, round_keys[i])
        R = [l ^ fo for l, fo in zip(L, f_output)]
        L = temp_R
    return permute(R + L, IP_INV)

def string_to_bits(text):
    bits = []
    for char in text:
        binval = bin(ord(char))[2:].rjust(8, '0')
        bits.extend([int(b) for b in binval])
    return bits

def bits_to_string(bits):
    chars = []
    for b in range(0, len(bits), 8):
        byte = bits[b:b+8]
        chars.append(chr(int(''.join([str(bit) for bit in byte]), 2)))
    return ''.join(chars)

import base64

def bits_to_base64(bits):
    byte_arr = bytearray()
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        byte_val = int(''.join(str(b) for b in byte), 2)
        byte_arr.append(byte_val)
    return base64.b64encode(byte_arr).decode('utf-8')

# --- ECB MODE ---
def pad_text(text):
    while len(text) % 8 != 0:
        text += ' '
    return text

def encrypt_ecb_mode(plaintext, key_text):
    plaintext = pad_text(plaintext)
    key_bits = string_to_bits(key_text)
    round_keys = generate_keys(key_bits)

    ciphertext_bits = []
    for i in range(0, len(plaintext), 8):
        block = plaintext[i:i+8]
        block_bits = string_to_bits(block)
        encrypted = encrypt_block(block_bits, round_keys)
        ciphertext_bits.extend(encrypted)
    return ciphertext_bits

def decrypt_ecb_mode(ciphertext_bits, key_text):
    key_bits = string_to_bits(key_text)
    round_keys = generate_keys(key_bits)

    decrypted_text = ''
    for i in range(0, len(ciphertext_bits), 64):
        block_bits = ciphertext_bits[i:i+64]
        decrypted_block = decrypt_block(block_bits, round_keys)
        decrypted_text += bits_to_string(decrypted_block)
    return decrypted_text.strip()

# --- CBC MODE ---
import random

def xor_bits(a, b):
    return [i ^ j for i, j in zip(a, b)]

def generate_iv():
    return [random.randint(0, 1) for _ in range(64)]

def encrypt_cbc_mode(plaintext, key_text, iv=None):
    plaintext = pad_text(plaintext)
    key_bits = string_to_bits(key_text)
    round_keys = generate_keys(key_bits)

    if iv is None:
        iv = generate_iv()

    ciphertext_bits = []
    previous_block = iv

    for i in range(0, len(plaintext), 8):
        block = plaintext[i:i+8]
        block_bits = string_to_bits(block)
        xor_block = xor_bits(block_bits, previous_block)
        encrypted = encrypt_block(xor_block, round_keys)
        ciphertext_bits.extend(encrypted)
        previous_block = encrypted

    return iv, ciphertext_bits

def decrypt_cbc_mode(ciphertext_bits, key_text, iv):
    key_bits = string_to_bits(key_text)
    round_keys = generate_keys(key_bits)

    decrypted_text = ''
    previous_block = iv

    for i in range(0, len(ciphertext_bits), 64):
        block = ciphertext_bits[i:i+64]
        decrypted = decrypt_block(block, round_keys)
        plain_block = xor_bits(decrypted, previous_block)
        decrypted_text += bits_to_string(plain_block)
        previous_block = block

    return decrypted_text.strip()

def run_gui():
    def encrypt():
        text = input_text.get("1.0", tk.END).strip()
        key = key_entry.get().strip()
        mode = mode_var.get()

        if len(key) != 8:
            messagebox.showerror("Key Error", "The key must be 8 characters!")
            return

        if mode == "CBC":
            iv_text = iv_entry.get().strip()
            if iv_text:
                if len(iv_text) != 64 or not all(c in '01' for c in iv_text):
                    messagebox.showerror("IV Error", "IV must be 64-bits and contain only 0/1!.")
                    return
                iv = [int(c) for c in iv_text]
            else:
                iv = generate_iv()
            final_iv, encrypted_bits = encrypt_cbc_mode(text, key, iv)
            result = f"IV: {final_iv}\nEncrypted CBC (Base64): {bits_to_base64(encrypted_bits)}"
        else:
            encrypted_bits = encrypt_ecb_mode(text, key)
            result = f"Encrypted ECB (Base64): {bits_to_base64(encrypted_bits)}"

        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, result)

    def decrypt():
        encrypted = encrypted_text.get("1.0", tk.END).strip()
        key = key_entry.get().strip()
        mode = mode_var.get()

        if len(key) != 8:
            messagebox.showerror("Key Error", "The key must be 8 characters!")
            return

        try:
            byte_data = base64.b64decode(encrypted)
            bits = []
            for byte in byte_data:
                bits.extend([int(b) for b in bin(byte)[2:].rjust(8, '0')])
        except Exception as e:
            messagebox.showerror("Base64 Error", "Enter valid Base64 encoded text!")
            return

        if mode == "CBC":
            iv_text = iv_entry.get().strip()
            if len(iv_text) != 64 or not all(c in '01' for c in iv_text):
                messagebox.showerror("IV Error", "IV must be entered for CBC decoding (64 bits, 0/1)!")
                return
            iv = [int(c) for c in iv_text]
            decrypted = decrypt_cbc_mode(bits, key, iv)
        else:
            decrypted = decrypt_ecb_mode(bits, key)

        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, decrypted)

    root = tk.Tk()
    root.title("DES Encryption - Decryption Algorithm GUI")
    root.geometry("600x700")

    tk.Label(root, text="Text to encrypt:").pack()
    input_text = scrolledtext.ScrolledText(root, height=5)
    input_text.pack(pady=5)

    tk.Label(root, text="Key (8 characters):").pack()
    key_entry = tk.Entry(root)
    key_entry.pack(pady=5)

    tk.Label(root, text="Modes (ECB/CBC):").pack()
    mode_var = tk.StringVar(value="ECB")
    tk.OptionMenu(root, mode_var, "ECB", "CBC").pack(pady=5)

    tk.Label(root, text="IV for CBC Mode (64 bit, optional):").pack()
    iv_entry = tk.Entry(root)
    iv_entry.pack(pady=5)

    tk.Button(root, text="Encrypt", command=encrypt).pack(pady=10)

    tk.Label(root, text="Encrypted (Base64) Text / Input to Decode:").pack()
    encrypted_text = scrolledtext.ScrolledText(root, height=5)
    encrypted_text.pack(pady=5)

    tk.Button(root, text="Decode", command=decrypt).pack(pady=10)

    tk.Label(root, text="Output:").pack()
    output_text = scrolledtext.ScrolledText(root, height=10)
    output_text.pack(pady=5)

    root.mainloop()

# Running
run_gui()

