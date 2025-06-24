# 🔐 DES Algorithm GUI Tool

This is a Python-based GUI application that implements the **Data Encryption Standard (DES)** for secure message encryption and decryption. The tool supports both **ECB (Electronic Codebook)** and **CBC (Cipher Block Chaining)** modes, allowing users to interactively encrypt or decrypt text using a given 8-character key.

## 💡 Features

- 🛠️ Built-in implementation of the full DES encryption algorithm (no external libraries used)
- 🔒 Supports both **ECB** and **CBC** encryption modes
- 🧪 Integrated base64 encoding/decoding for readable ciphertext
- 🧑‍💻 User-friendly GUI built with **Tkinter**
- 🧬 Optional manual or randomly generated **IV** for CBC mode
- 🧾 Automatic padding to match DES 64-bit block size
- ✅ Real-time encrypt/decrypt with validation

## 🖥️ How to Use

- Enter plain text in the input box.
- Specify an 8-character key for DES.
- Select encryption mode: ECB or CBC.
- For CBC: Enter a binary string as IV (optional), or leave blank to auto-generate a random IV.
- Click Encrypt to get base64-encoded ciphertext.
- If you want to decrypt, paste ciphertext, enter the same key and IV (if CBC), and click "Decode" to get original message.

## 📌 Notes

- Key must be exactly 8 characters.
- Padding is applied automatically.
- IV (Initialization Vector) is required for CBC mode.
- CBC mode is more secure due to chaining blocks.

## ⚠️ Disclaimer

DES is a legacy algorithm and not secure for modern cryptographic needs.
This tool is for educational purposes only.

## 📷 Screenshots

![Screenshot 2025-06-24 111100](https://github.com/user-attachments/assets/9a85ebb7-2904-4416-b468-724846f7827c)

![Screenshot 2025-06-24 111138](https://github.com/user-attachments/assets/b6e59f06-8bf2-48ac-9758-2199f12f30d4)

### 🔧 Requirements

- Python 3.x  
- Built-in libraries used:
  - `tkinter`
  - `base64`
  - `random`

### ▶️ Run the App

```bash
python desalgorithm.py
