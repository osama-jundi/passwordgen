import tkinter as tk
from tkinter import messagebox
import random
import string
import pyperclip
import pandas as pd
import os
from datetime import datetime


EXCEL_FILE = "password_manager.xlsx"


root = tk.Tk()
root.title("Password Manager")


password_length = tk.StringVar(value="12")
include_upper = tk.BooleanVar(value=True)
include_lower = tk.BooleanVar(value=True)
include_numbers = tk.BooleanVar(value=True)
include_special = tk.BooleanVar(value=True)
generated_password = tk.StringVar()
password_label = tk.StringVar()
password_key = tk.StringVar()



def load_existing_passwords():

    if os.path.exists(EXCEL_FILE):
        return pd.read_excel(EXCEL_FILE)
    else:
        return pd.DataFrame(columns=["Label", "Password", "Description", "Last Updated"])


def save_to_excel(label, password, description):

    try:

        df = load_existing_passwords()


        if label in df["Label"].values:
            df.loc[df["Label"] == label, ["Password", "Description", "Last Updated"]] = [
                password,
                description,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ]
            action = "updated"
        else:

            new_row = pd.DataFrame([{
                "Label": label,
                "Password": password,
                "Description": description,
                "Last Updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }])
            df = pd.concat([df, new_row], ignore_index=True)
            action = "saved"


        df.to_excel(EXCEL_FILE, index=False)
        messagebox.showinfo("Success", f"Password for '{label}' {action}!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save: {e}")


def generate_password():

    try:
        length = int(password_length.get())
        if length < 4 or length > 32:
            messagebox.showerror("Error", "Length must be between 4 and 32!")
            return
    except ValueError:
        messagebox.showerror("Error", "Please enter a valid number!")
        return


    if not (include_upper.get() or include_lower.get() or include_numbers.get() or include_special.get()):
        messagebox.showerror("Error", "Select at least one character type!")
        return


    chars = ""
    if include_upper.get(): chars += string.ascii_uppercase
    if include_lower.get(): chars += string.ascii_lowercase
    if include_numbers.get(): chars += string.digits
    if include_special.get(): chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"

    try:
        password = "".join(random.choice(chars) for _ in range(length))
        generated_password.set(password)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to generate password: {e}")


def copy_to_clipboard():
    if generated_password.get():
        pyperclip.copy(generated_password.get())
        messagebox.showinfo("Copied!", "Password copied to clipboard!")
    else:
        messagebox.showerror("Error", "No password generated yet!")


def save_password():
    label = password_label.get().strip()
    key = password_key.get().strip()
    password = generated_password.get()

    if not label or not password:
        messagebox.showerror("Error", "Label and password cannot be empty!")
        return

    save_to_excel(label, password, key if key else "N/A")



tk.Label(root, text="Password Length:").grid(row=0, column=0, sticky="w")
tk.Entry(root, textvariable=password_length, width=5).grid(row=0, column=1, sticky="w")


tk.Checkbutton(root, text="Uppercase (A-Z)", variable=include_upper).grid(row=1, column=0, sticky="w")
tk.Checkbutton(root, text="Lowercase (a-z)", variable=include_lower).grid(row=2, column=0, sticky="w")
tk.Checkbutton(root, text="Numbers (0-9)", variable=include_numbers).grid(row=3, column=0, sticky="w")
tk.Checkbutton(root, text="Special (!@#...)", variable=include_special).grid(row=4, column=0, sticky="w")


tk.Label(root, text="Password For:").grid(row=5, column=0, sticky="w")
tk.Entry(root, textvariable=password_label, width=25).grid(row=5, column=1, sticky="w")

tk.Label(root, text="Description:").grid(row=6, column=0, sticky="w")
tk.Entry(root, textvariable=password_key, width=25).grid(row=6, column=1, sticky="w")


tk.Entry(root, textvariable=generated_password, width=25, state="readonly").grid(row=7, column=0, columnspan=2, pady=5)


tk.Button(root, text="Generate", command=generate_password).grid(row=8, column=0, pady=5)
tk.Button(root, text="Copy", command=copy_to_clipboard).grid(row=8, column=1, pady=5)
tk.Button(root, text="Save", command=save_password).grid(row=9, column=0, columnspan=2, pady=5)

root.mainloop()