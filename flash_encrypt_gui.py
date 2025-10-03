#!/usr/bin/env python3
"""
flash_encrypt_gui.py
GUI wrapper around the flash drive encryption tool.

Requires: pycryptodome
"""

import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from pathlib import Path
from flash_encrypt import process_path, DEFAULT_MAX_BYTES  # reuse logic from previous script

class EncryptGUI:
    def __init__(self, root):
        self.root = root
        root.title("Flash Drive Encryptor (AES-GCM)")
        root.geometry("600x400")

        # Path selection
        tk.Label(root, text="Target Path:").pack(anchor="w", padx=10, pady=2)
        path_frame = tk.Frame(root)
        path_frame.pack(fill="x", padx=10)
        self.path_entry = tk.Entry(path_frame)
        self.path_entry.pack(side="left", fill="x", expand=True)
        tk.Button(path_frame, text="Browse", command=self.browse_path).pack(side="right", padx=5)

        # Passphrase
        tk.Label(root, text="Passphrase:").pack(anchor="w", padx=10, pady=2)
        self.pass_entry = tk.Entry(root, show="*")
        self.pass_entry.pack(fill="x", padx=10, pady=2)

        # Mode
        self.mode_var = tk.StringVar(value="encrypt")
        mode_frame = tk.Frame(root)
        mode_frame.pack(anchor="w", padx=10, pady=5)
        tk.Label(mode_frame, text="Mode:").pack(side="left")
        tk.Radiobutton(mode_frame, text="Encrypt", variable=self.mode_var, value="encrypt").pack(side="left")
        tk.Radiobutton(mode_frame, text="Decrypt", variable=self.mode_var, value="decrypt").pack(side="left")

        # Options
        self.recursive_var = tk.BooleanVar(value=True)
        self.delete_var = tk.BooleanVar(value=False)
        tk.Checkbutton(root, text="Recurse into subdirectories", variable=self.recursive_var).pack(anchor="w", padx=10)
        tk.Checkbutton(root, text="Delete originals after operation (DANGEROUS)", variable=self.delete_var).pack(anchor="w", padx=10)

        # Run button
        tk.Button(root, text="Run", command=self.run_task).pack(pady=10)

        # Log output
        tk.Label(root, text="Log:").pack(anchor="w", padx=10)
        self.log = scrolledtext.ScrolledText(root, height=10, state="disabled")
        self.log.pack(fill="both", expand=True, padx=10, pady=5)

    def browse_path(self):
        path = filedialog.askdirectory() or filedialog.askopenfilename()
        if path:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, path)

    def append_log(self, msg):
        self.log.config(state="normal")
        self.log.insert(tk.END, msg + "\n")
        self.log.yview(tk.END)
        self.log.config(state="disabled")
        self.root.update_idletasks()

    def run_task(self):
        path = self.path_entry.get().strip()
        passphrase = self.pass_entry.get().strip()
        mode = self.mode_var.get()
        recursive = self.recursive_var.get()
        delete_originals = self.delete_var.get()

        if not path:
            messagebox.showerror("Error", "Please select a target path.")
            return
        if not passphrase:
            messagebox.showerror("Error", "Please enter a passphrase.")
            return

        target = Path(path)
        if not target.exists():
            messagebox.showerror("Error", f"Path does not exist: {path}")
            return

        # Run in background thread so GUI doesn't freeze
        def worker():
            try:
                self.append_log(f"Starting {mode} on {path}...")
                process_path(
                    root=target,
                    passphrase=passphrase,
                    mode=mode,
                    recursive=recursive,
                    delete_originals=delete_originals,
                    max_bytes=DEFAULT_MAX_BYTES,
                )
                self.append_log("Done.")
                messagebox.showinfo("Finished", f"{mode.capitalize()} completed successfully.")
            except Exception as e:
                self.append_log(f"Error: {e}")
                messagebox.showerror("Error", str(e))

        threading.Thread(target=worker, daemon=True).start()


if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptGUI(root)
    root.mainloop()
