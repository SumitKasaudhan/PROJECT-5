import os
import base64
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import time
from cryptography.fernet import Fernet
import shutil

class RansomwareSimulator:
    def __init__(self, root):
        self.root = root
        self.root.title("Ransomware Simulator (EDUCATIONAL USE ONLY)")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        self.root.configure(bg="#2c3e50")
        
        # Set icon and styling
        self.style = ttk.Style()
        self.style.configure("TButton", font=("Arial", 12))
        self.style.configure("TLabel", font=("Arial", 12), background="#2c3e50", foreground="white")
        self.style.configure("Header.TLabel", font=("Arial", 16, "bold"), background="#2c3e50", foreground="white")
        self.style.configure("Warning.TLabel", font=("Arial", 12, "bold"), background="#2c3e50", foreground="#e74c3c")
        
        # Variables
        self.target_dir = tk.StringVar()
        self.key = tk.StringVar()
        self.status = tk.StringVar(value="Ready")
        self.progress = tk.DoubleVar(value=0)
        self.encrypted_files = []
        self.is_encrypted = False
        
        self.create_widgets()
        self.show_disclaimer()
    
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Disclaimer and warning
        disclaimer_frame = ttk.Frame(main_frame)
        disclaimer_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(disclaimer_frame, text="⚠️ EDUCATIONAL PURPOSE ONLY ⚠️", 
                 style="Warning.TLabel").pack(pady=5)
        ttk.Label(disclaimer_frame, 
                 text="This simulator demonstrates ransomware behavior for educational purposes.", 
                 wraplength=700).pack(pady=2)
        ttk.Label(disclaimer_frame, 
                 text="NEVER use this knowledge for malicious purposes.", 
                 style="Warning.TLabel").pack(pady=5)
        
        # Directory selection
        dir_frame = ttk.Frame(main_frame)
        dir_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(dir_frame, text="Target Directory:", style="Header.TLabel").pack(anchor=tk.W, pady=5)
        ttk.Label(dir_frame, 
                 text="Select a directory containing test files ONLY. DO NOT select important folders!", 
                 style="Warning.TLabel").pack(anchor=tk.W)
        
        dir_select_frame = ttk.Frame(dir_frame)
        dir_select_frame.pack(fill=tk.X, pady=5)
        
        ttk.Entry(dir_select_frame, textvariable=self.target_dir, width=60).pack(side=tk.LEFT, padx=5)
        ttk.Button(dir_select_frame, text="Browse", command=self.browse_directory).pack(side=tk.LEFT, padx=5)
        
        # Create test files button
        ttk.Button(dir_frame, text="Create Test Files", command=self.create_test_files).pack(anchor=tk.W, pady=5)
        
        # Key management
        key_frame = ttk.Frame(main_frame)
        key_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(key_frame, text="Encryption Key:", style="Header.TLabel").pack(anchor=tk.W, pady=5)
        
        key_input_frame = ttk.Frame(key_frame)
        key_input_frame.pack(fill=tk.X, pady=5)
        
        self.key_entry = ttk.Entry(key_input_frame, textvariable=self.key, width=60, show="*")
        self.key_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(key_input_frame, text="Generate Key", command=self.generate_key).pack(side=tk.LEFT, padx=5)
        ttk.Button(key_input_frame, text="Show/Hide", command=self.toggle_key_visibility).pack(side=tk.LEFT, padx=5)
        
        # Action buttons
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=tk.X, pady=10)
        
        self.encrypt_btn = ttk.Button(action_frame, text="Encrypt Files", command=self.start_encryption)
        self.encrypt_btn.pack(side=tk.LEFT, padx=5)
        
        self.decrypt_btn = ttk.Button(action_frame, text="Decrypt Files", command=self.start_decryption, state=tk.DISABLED)
        self.decrypt_btn.pack(side=tk.LEFT, padx=5)
        
        # Progress and status
        progress_frame = ttk.Frame(main_frame)
        progress_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(progress_frame, text="Progress:").pack(anchor=tk.W, pady=5)
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress, length=700, mode="determinate")
        self.progress_bar.pack(fill=tk.X, pady=5)
        
        ttk.Label(progress_frame, text="Status:").pack(anchor=tk.W, pady=5)
        ttk.Label(progress_frame, textvariable=self.status).pack(anchor=tk.W, pady=5)
        
        # File list
        list_frame = ttk.Frame(main_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        ttk.Label(list_frame, text="Files:", style="Header.TLabel").pack(anchor=tk.W, pady=5)
        
        # Create a frame with scrollbar for the file list
        file_list_frame = ttk.Frame(list_frame)
        file_list_frame.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(file_list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.file_listbox = tk.Listbox(file_list_frame, height=10, width=80, yscrollcommand=scrollbar.set)
        self.file_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.file_listbox.yview)
    
    def show_disclaimer(self):
        disclaimer = """⚠️ IMPORTANT DISCLAIMER ⚠️

This application is designed SOLELY for EDUCATIONAL PURPOSES to demonstrate how ransomware operates.

By using this simulator, you agree to:
1. Use it ONLY on test files in a controlled environment
2. NEVER use this knowledge for malicious purposes
3. Take full responsibility for any consequences of using this tool

Misuse of this knowledge is illegal and unethical.

Do you understand and agree to use this simulator responsibly?"""
        
        result = messagebox.askokcancel("Educational Purpose Disclaimer", disclaimer, icon=messagebox.WARNING)
        if not result:
            self.root.destroy()
    
    def browse_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.target_dir.set(directory)
            self.update_file_list()
    
    def create_test_files(self):
        if not self.target_dir.get():
            messagebox.showerror("Error", "Please select a target directory first")
            return
            
        test_dir = os.path.join(self.target_dir.get(), "test_files")
        try:
            if not os.path.exists(test_dir):
                os.makedirs(test_dir)
                
            # Create sample text files
            for i in range(5):
                with open(os.path.join(test_dir, f"document_{i}.txt"), "w") as f:
                    f.write(f"This is a test document {i} for ransomware simulation.\n")
                    f.write("This file contains sample text that would be encrypted by ransomware.\n")
                    f.write(f"Sample content line {i+1}\n")
                    f.write(f"Sample content line {i+2}\n")
                    
            # Create a sample image file (just a text file with .jpg extension)
            with open(os.path.join(test_dir, "sample_image.jpg"), "w") as f:
                f.write("This is a placeholder for an image file.\n")
                
            # Create a sample document file
            with open(os.path.join(test_dir, "important_document.docx"), "w") as f:
                f.write("This is a placeholder for an important document.\n")
                
            self.target_dir.set(test_dir)
            self.update_file_list()
            messagebox.showinfo("Success", f"Created test files in {test_dir}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create test files: {str(e)}")
    
    def generate_key(self):
        key = Fernet.generate_key()
        self.key.set(key.decode())
        messagebox.showinfo("Key Generated", "A new encryption key has been generated. Keep this key safe to decrypt your files later.")
    
    def toggle_key_visibility(self):
        if self.key_entry.cget("show") == "*":
            self.key_entry.config(show="")
        else:
            self.key_entry.config(show="*")
    
    def update_file_list(self):
        self.file_listbox.delete(0, tk.END)
        directory = self.target_dir.get()
        if not directory or not os.path.exists(directory):
            return
            
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(".encrypted"):
                    status = "[ENCRYPTED]"
                else:
                    status = "[NORMAL]"
                self.file_listbox.insert(tk.END, f"{status} {os.path.join(root, file)}")
    
    def validate_inputs(self):
        if not self.target_dir.get() or not os.path.exists(self.target_dir.get()):
            messagebox.showerror("Error", "Please select a valid target directory")
            return False
            
        if not self.key.get():
            messagebox.showerror("Error", "Please generate or enter an encryption key")
            return False
            
        try:
            # Validate the key format
            key_bytes = self.key.get().encode()
            Fernet(key_bytes)
        except Exception:
            messagebox.showerror("Error", "Invalid encryption key format")
            return False
            
        return True
    
    def start_encryption(self):
        if not self.validate_inputs():
            return
            
        # Double confirmation
        confirm = messagebox.askokcancel(
            "Confirm Encryption", 
            "⚠️ WARNING: You are about to encrypt all files in the selected directory. " +
            "This simulates a ransomware attack. " +
            "\n\nProceed ONLY if these are test files you can afford to lose. " +
            "\n\nDo you want to continue?",
            icon=messagebox.WARNING
        )
        
        if not confirm:
            return
            
        # Start encryption in a separate thread
        self.encrypt_btn.config(state=tk.DISABLED)
        self.decrypt_btn.config(state=tk.DISABLED)
        
        threading.Thread(target=self.encrypt_files, daemon=True).start()
    
    def start_decryption(self):
        if not self.validate_inputs():
            return
            
        # Start decryption in a separate thread
        self.encrypt_btn.config(state=tk.DISABLED)
        self.decrypt_btn.config(state=tk.DISABLED)
        
        threading.Thread(target=self.decrypt_files, daemon=True).start()
    
    def encrypt_files(self):
        try:
            directory = self.target_dir.get()
            key = self.key.get().encode()
            cipher = Fernet(key)
            
            # Get list of files to encrypt
            files_to_encrypt = []
            for root, _, files in os.walk(directory):
                for file in files:
                    if not file.endswith(".encrypted"):  # Skip already encrypted files
                        file_path = os.path.join(root, file)
                        files_to_encrypt.append(file_path)
            
            total_files = len(files_to_encrypt)
            if total_files == 0:
                self.status.set("No files to encrypt")
                self.root.after(0, lambda: self.encrypt_btn.config(state=tk.NORMAL))
                return
                
            self.encrypted_files = []
            
            # Process each file
            for i, file_path in enumerate(files_to_encrypt):
                try:
                    # Update status
                    file_name = os.path.basename(file_path)
                    self.status.set(f"Encrypting {i+1}/{total_files}: {file_name}")
                    self.progress.set((i / total_files) * 100)
                    
                    # Read file content
                    with open(file_path, "rb") as file:
                        file_data = file.read()
                    
                    # Encrypt the data
                    encrypted_data = cipher.encrypt(file_data)
                    
                    # Write encrypted data
                    encrypted_file_path = file_path + ".encrypted"
                    with open(encrypted_file_path, "wb") as file:
                        file.write(encrypted_data)
                    
                    # Remove original file
                    os.remove(file_path)
                    
                    # Add to encrypted files list
                    self.encrypted_files.append(encrypted_file_path)
                    
                    # Simulate some processing time for educational purposes
                    time.sleep(0.1)
                except Exception as e:
                    self.status.set(f"Error encrypting {file_name}: {str(e)}")
            
            # Create ransom note
            self.create_ransom_note(directory)
            
            # Update UI
            self.progress.set(100)
            self.status.set(f"Encryption complete. {len(self.encrypted_files)} files encrypted.")
            self.is_encrypted = True
            
            # Update buttons state
            self.root.after(0, lambda: self.decrypt_btn.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.encrypt_btn.config(state=tk.DISABLED))
            
            # Update file list
            self.root.after(0, self.update_file_list)
            
            # Show ransom message
            self.root.after(0, self.show_ransom_message)
            
        except Exception as e:
            self.status.set(f"Encryption failed: {str(e)}")
            self.root.after(0, lambda: self.encrypt_btn.config(state=tk.NORMAL))
    
    def decrypt_files(self):
        try:
            directory = self.target_dir.get()
            key = self.key.get().encode()
            cipher = Fernet(key)
            
            # Get list of files to decrypt
            files_to_decrypt = []
            for root, _, files in os.walk(directory):
                for file in files:
                    if file.endswith(".encrypted"):  # Only decrypt encrypted files
                        file_path = os.path.join(root, file)
                        files_to_decrypt.append(file_path)
            
            total_files = len(files_to_decrypt)
            if total_files == 0:
                self.status.set("No encrypted files found")
                self.root.after(0, lambda: self.decrypt_btn.config(state=tk.DISABLED))
                self.root.after(0, lambda: self.encrypt_btn.config(state=tk.NORMAL))
                return
                
            # Process each file
            for i, file_path in enumerate(files_to_decrypt):
                try:
                    # Update status
                    file_name = os.path.basename(file_path)
                    self.status.set(f"Decrypting {i+1}/{total_files}: {file_name}")
                    self.progress.set((i / total_files) * 100)
                    
                    # Read encrypted file content
                    with open(file_path, "rb") as file:
                        encrypted_data = file.read()
                    
                    # Decrypt the data
                    try:
                        decrypted_data = cipher.decrypt(encrypted_data)
                    except Exception:
                        self.status.set(f"Wrong decryption key for {file_name}")
                        continue
                    
                    # Write decrypted data
                    original_file_path = file_path[:-10]  # Remove .encrypted extension
                    with open(original_file_path, "wb") as file:
                        file.write(decrypted_data)
                    
                    # Remove encrypted file
                    os.remove(file_path)
                    
                    # Simulate some processing time for educational purposes
                    time.sleep(0.1)
                except Exception as e:
                    self.status.set(f"Error decrypting {file_name}: {str(e)}")
            
            # Remove ransom note
            ransom_note_path = os.path.join(directory, "RANSOM_NOTE.txt")
            if os.path.exists(ransom_note_path):
                os.remove(ransom_note_path)
            
            # Update UI
            self.progress.set(100)
            self.status.set(f"Decryption complete. {total_files} files decrypted.")
            self.is_encrypted = False
            
            # Update buttons state
            self.root.after(0, lambda: self.encrypt_btn.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.decrypt_btn.config(state=tk.DISABLED))
            
            # Update file list
            self.root.after(0, self.update_file_list)
            
            # Show success message
            self.root.after(0, lambda: messagebox.showinfo("Decryption Complete", 
                                                         f"Successfully decrypted {total_files} files."))
            
        except Exception as e:
            self.status.set(f"Decryption failed: {str(e)}")
            self.root.after(0, lambda: self.decrypt_btn.config(state=tk.NORMAL))
    
    def create_ransom_note(self, directory):
        ransom_note = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                          !!! YOUR FILES ARE ENCRYPTED !!!                   ║
╚══════════════════════════════════════════════════════════════════════════════╝

[THIS IS AN EDUCATIONAL SIMULATION ONLY]

What happened to your files?
All of your files have been encrypted with a strong encryption algorithm.
Without the correct decryption key, it is impossible to recover your files.

How to recover your files?
To decrypt your files, you need to:
1. Keep the encryption key that was used to encrypt your files
2. Use the decryption function in the simulator

IMPORTANT LESSONS:
- Real ransomware would demand payment in cryptocurrency
- Never pay the ransom in real attacks - there's no guarantee you'll get your files back
- Always maintain secure backups of important files
- Use strong antivirus and keep your system updated
- Be cautious of suspicious emails and downloads

╔══════════════════════════════════════════════════════════════════════════════╗
║                      EDUCATIONAL PURPOSE ONLY                                ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
        
        with open(os.path.join(directory, "RANSOM_NOTE.txt"), "w") as f:
            f.write(ransom_note)
    
    def show_ransom_message(self):
        ransom_window = tk.Toplevel(self.root)
        ransom_window.title("⚠️ YOUR FILES HAVE BEEN ENCRYPTED ⚠️")
        ransom_window.geometry("700x500")
        ransom_window.configure(bg="#e74c3c")
        
        # Make window modal
        ransom_window.grab_set()
        ransom_window.transient(self.root)
        
        # Add content
        frame = ttk.Frame(ransom_window, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header_label = ttk.Label(frame, text="YOUR FILES HAVE BEEN ENCRYPTED", 
                               font=("Arial", 18, "bold"))
        header_label.pack(pady=10)
        
        # Simulation notice
        sim_label = ttk.Label(frame, text="[THIS IS AN EDUCATIONAL SIMULATION]", 
                             font=("Arial", 12, "italic"))
        sim_label.pack(pady=5)
        
        # Message
        message = """All your files have been encrypted with a strong encryption algorithm.

In a real ransomware attack, you would be asked to pay a ransom to get the decryption key.

However, this is just a simulation for educational purposes.

To recover your files, use the decryption function in the main window with the key you generated earlier.

Lessons to learn:
• Always maintain secure backups
• Use strong antivirus protection
• Be cautious of suspicious emails and downloads
• Keep your operating system and software updated
• Never pay the ransom in real attacks"""
        
        message_label = ttk.Label(frame, text=message, wraplength=600, 
                                font=("Arial", 12))
        message_label.pack(pady=20)
        
        # Close button
        close_button = ttk.Button(frame, text="I Understand", 
                                command=ransom_window.destroy)
        close_button.pack(pady=10)


def main():
    # Check if cryptography module is installed
    try:
        import cryptography
    except ImportError:
        print("The cryptography module is required. Please install it using:")
        print("pip install cryptography")
        return
    
    root = tk.Tk()
    app = RansomwareSimulator(root)
    root.mainloop()

if __name__ == "__main__":
    main()