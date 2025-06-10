import tkinter as tk
from tkinter import messagebox
import re


def check_password_strength(password):
    length_error = len(password) < 8
    digit_error = re.search(r"\d", password) is None
    uppercase_error = re.search(r"[A-Z]", password) is None
    lowercase_error = re.search(r"[a-z]", password) is None
    symbol_error = re.search(r"[!@#$%^&*()_+=\-{};:'\"\\|,.<>/?]", password) is None

    errors = [length_error, digit_error, uppercase_error, lowercase_error, symbol_error]
    score = errors.count(False)

    if score <= 2:
        return "Weak", "Try adding uppercase letters, numbers, and special characters."
    elif score == 3 or score == 4:
        return "Medium", "Consider using more unique characters and increasing the length."
    else:
        return "Strong", "Great! Your password is strong."


def on_check():
    password = entry.get()
    if not password:
        messagebox.showwarning("Warning", "Please enter a password")
        return
    strength, suggestion = check_password_strength(password)
    result_label.config(text=f"Password Strength: {strength}")
    suggestion_label.config(text=suggestion)


root = tk.Tk()
root.title("Password Complexity Checker")
root.geometry("500x300")
root.resizable(False, False)


label = tk.Label(root, text="Enter your password:", font=("Arial", 12))
label.pack(pady=10)

entry = tk.Entry(root, width=40, show="*", font=("Arial", 12))
entry.pack(pady=5)

check_button = tk.Button(root, text="Check Password", command=on_check, font=("Arial", 12))
check_button.pack(pady=10)

result_label = tk.Label(root, text="", font=("Arial", 14, "bold"), fg="blue")
result_label.pack(pady=5)

suggestion_label = tk.Label(root, text="", font=("Arial", 11), fg="gray")
suggestion_label.pack(pady=5)

root.mainloop()
