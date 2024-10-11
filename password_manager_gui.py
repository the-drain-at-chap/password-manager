import tkinter as tk
from tkinter import ttk, messagebox
import random
import string
import hashlib
import json
import base64
import sys
import threading
from cryptography.fernet import Fernet
from collections import deque
import pystray
from PIL import Image, ImageDraw

class PasswordManager:
    def __init__(self):
        self.key = None
        self.password_file = "passwords.json"
        self.password_dict = {}

    def create_key(self, master_password):
        salt = b'salt_'  # In a real application, use a random salt and store it securely
        key = hashlib.pbkdf2_hmac(
            'sha256',
            master_password.encode('utf-8'),
            salt,
            100000  # Number of iterations
        )
        self.key = base64.urlsafe_b64encode(key)

    def load_passwords(self):
        try:
            with open(self.password_file, "r") as f:
                encrypted_data = f.read()
                fernet = Fernet(self.key)
                decrypted_data = fernet.decrypt(encrypted_data.encode())
                self.password_dict = json.loads(decrypted_data)
        except FileNotFoundError:
            pass

    def save_passwords(self):
        fernet = Fernet(self.key)
        encrypted_data = fernet.encrypt(json.dumps(self.password_dict).encode())
        with open(self.password_file, "w") as f:
            f.write(encrypted_data.decode())

    def generate_password(self):
        while True:
            length = random.randint(15, 20)
            characters = string.ascii_letters + string.digits + string.punctuation
            password = ''.join(random.choice(characters) for _ in range(length))
            
            # Check if this password is already used
            if not self.is_password_used(password):
                return password

    def is_password_used(self, password):
        return any(account['password'] == password for account in self.password_dict.values())

    def add_account(self, account_name, username, password):
        if self.is_password_used(password):
            raise ValueError("This password is already in use. Please generate a new one.")
        self.password_dict[account_name] = {"username": username, "password": password}
        self.save_passwords()

    def get_account(self, account_name):
        return self.password_dict.get(account_name)

    def remove_account(self, account_name):
        if account_name in self.password_dict:
            del self.password_dict[account_name]
            self.save_passwords()
            return True
        return False

    def list_accounts(self):
        return list(self.password_dict.keys())

    def change_master_password(self, new_master_password):
        # Decrypt all passwords with the old key
        decrypted_data = self.password_dict

        # Create a new key with the new master password
        self.create_key(new_master_password)

        # Re-encrypt all passwords with the new key
        self.password_dict = decrypted_data
        self.save_passwords()

class PasswordManagerGUI:
    def __init__(self, master):
        self.master = master
        self.pm = PasswordManager()
        self.master.title("Password Manager")
        self.master.geometry("400x300")
        self.master.withdraw()  # Hide the main window initially
        self.center_window(self.master)  # Center the main window
        
        self.setup_gui()
        self.setup_hotkeys()  # Add this line


    def setup_hotkeys(self):
        self.master.bind('<Control-f>', lambda e: self.focus_search())
        self.master.bind('<Control-c>', lambda e: self.copy_password())

    def focus_search(self):
        current_tab = self.notebook.index(self.notebook.select())
        if current_tab == 1:  # List of Accounts tab
            self.list_search_var.set("")
            self.notebook.winfo_children()[1].winfo_children()[0].winfo_children()[1].focus()
        elif current_tab == 2:  # Remove Account tab
            self.remove_search_var.set("")
            self.notebook.winfo_children()[2].winfo_children()[0].winfo_children()[1].focus()
    
    def center_window(self, window):
        window.update_idletasks()
        width = window.winfo_width()
        height = window.winfo_height()
        x = (window.winfo_screenwidth() // 2) - (width // 2)
        y = (window.winfo_screenheight() // 2) - (height // 2)
        window.geometry('{}x{}+{}+{}'.format(width, height, x, y))
        
    def setup_gui(self):
        self.notebook = ttk.Notebook(self.master)
        self.notebook.pack(expand=True, fill='both', padx=10, pady=10)
        
        self.setup_add_tab()
        self.setup_list_tab()
        self.setup_remove_tab()
        self.setup_change_master_password_tab()
        
    def setup_add_tab(self):
        add_frame = ttk.Frame(self.notebook)
        self.notebook.add(add_frame, text="Add New Account")
        
        ttk.Label(add_frame, text="Account Name:").grid(row=0, column=0, padx=5, pady=5)
        self.account_entry = ttk.Entry(add_frame)
        self.account_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(add_frame, text="Username:").grid(row=1, column=0, padx=5, pady=5)
        self.username_entry = ttk.Entry(add_frame)
        self.username_entry.grid(row=1, column=1, padx=5, pady=5)
        
        add_button = ttk.Button(add_frame, text="Add Account", command=self.add_account)
        add_button.grid(row=2, column=0, columnspan=2, padx=5, pady=5)
        
    def setup_list_tab(self):
        list_frame = ttk.Frame(self.notebook)
        self.notebook.add(list_frame, text="List of Accounts")
        
        # Add search bar
        search_frame = ttk.Frame(list_frame)
        search_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=5)
        self.list_search_var = tk.StringVar()
        self.list_search_var.trace("w", lambda name, index, mode: self.update_list())
        ttk.Entry(search_frame, textvariable=self.list_search_var).pack(side=tk.LEFT, expand=True, fill='x')

        self.account_listbox = tk.Listbox(list_frame)
        self.account_listbox.pack(expand=True, fill='both', padx=5, pady=5)
        self.account_listbox.bind('<<ListboxSelect>>', self.on_account_select)
        
        self.account_info = tk.StringVar()
        ttk.Label(list_frame, textvariable=self.account_info).pack(padx=5, pady=5)
        
        self.copy_button = ttk.Button(list_frame, text="Copy Password", command=self.copy_password)
        self.copy_button.pack(padx=5, pady=5)
        self.copy_button.config(state='disabled')
        
    def setup_remove_tab(self):
        remove_frame = ttk.Frame(self.notebook)
        self.notebook.add(remove_frame, text="Remove Account")
        
        # Add search bar
        search_frame = ttk.Frame(remove_frame)
        search_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=5)
        self.remove_search_var = tk.StringVar()
        self.remove_search_var.trace("w", lambda name, index, mode: self.update_remove_list())
        ttk.Entry(search_frame, textvariable=self.remove_search_var).pack(side=tk.LEFT, expand=True, fill='x')

        self.remove_listbox = tk.Listbox(remove_frame, selectmode=tk.MULTIPLE)
        self.remove_listbox.pack(expand=True, fill='both', padx=5, pady=5)
        
        remove_button = ttk.Button(remove_frame, text="Remove Selected Accounts", command=self.remove_accounts)
        remove_button.pack(padx=5, pady=5)

    def update_list(self):
        search_term = self.list_search_var.get().lower()
        self.account_listbox.delete(0, tk.END)
        for account in self.pm.list_accounts():
            if search_term in account.lower():
                self.account_listbox.insert(tk.END, account)

    def update_remove_list(self):
        search_term = self.remove_search_var.get().lower()
        self.remove_listbox.delete(0, tk.END)
        for account in self.pm.list_accounts():
            if search_term in account.lower():
                self.remove_listbox.insert(tk.END, account)

    def setup_change_master_password_tab(self):
        change_pass_frame = ttk.Frame(self.notebook)
        self.notebook.add(change_pass_frame, text="Change Master Password")

        ttk.Label(change_pass_frame, text="Current Master Password:").grid(row=0, column=0, padx=5, pady=5)
        self.current_master_pass_entry = ttk.Entry(change_pass_frame, show="*")
        self.current_master_pass_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(change_pass_frame, text="New Master Password:").grid(row=1, column=0, padx=5, pady=5)
        self.new_master_pass_entry = ttk.Entry(change_pass_frame, show="*")
        self.new_master_pass_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(change_pass_frame, text="Confirm New Master Password:").grid(row=2, column=0, padx=5, pady=5)
        self.confirm_master_pass_entry = ttk.Entry(change_pass_frame, show="*")
        self.confirm_master_pass_entry.grid(row=2, column=1, padx=5, pady=5)

        change_button = ttk.Button(change_pass_frame, text="Change Master Password", command=self.change_master_password)
        change_button.grid(row=3, column=0, columnspan=2, padx=5, pady=5)
        
    def add_account(self):
        account_name = self.account_entry.get()
        username = self.username_entry.get()
        
        if account_name and username:
            try:
                password = self.pm.generate_password()
                self.pm.add_account(account_name, username, password)
                self.account_entry.delete(0, tk.END)
                self.username_entry.delete(0, tk.END)
                self.refresh_account_lists()
                self.show_new_password(password)
            except ValueError as e:
                messagebox.showerror("Error", str(e))
        else:
            messagebox.showerror("Error", "Please fill in all fields.")
        
    def show_new_password(self, password):
        new_window = tk.Toplevel(self.master)
        new_window.title("New Password")
        new_window.geometry("300x100")
        self.center_window(new_window)
        
        ttk.Label(new_window, text=f"Generated Password: {password}").pack(padx=10, pady=10)
        
        def copy_and_close():
            self.master.clipboard_clear()
            self.master.clipboard_append(password)
            self.schedule_clipboard_clear()  # Add this line
            new_window.destroy()
        
        copy_button = ttk.Button(new_window, text="Copy Password", command=copy_and_close)
        copy_button.pack(padx=10, pady=10)
        
    def on_account_select(self, event):
        selection = event.widget.curselection()
        if selection:
            account_name = event.widget.get(selection[0])
            account = self.pm.get_account(account_name)
            if account:
                self.account_info.set(f"Username: {account['username']}\nPassword: {account['password']}")
                self.copy_button.config(state='normal')
            else:
                self.account_info.set("Account information not found.")
                self.copy_button.config(state='disabled')
        
    def copy_password(self):
        selection = self.account_listbox.curselection()
        if selection:
            account_name = self.account_listbox.get(selection[0])
            account = self.pm.get_account(account_name)
            if account:
                self.master.clipboard_clear()
                self.master.clipboard_append(account['password'])
                self.schedule_clipboard_clear()

    def schedule_clipboard_clear(self):
        threading.Timer(30, self.clear_clipboard).start()

    def clear_clipboard(self):
        self.master.clipboard_clear()
        self.master.clipboard_append("")

        
    def remove_accounts(self):
        selected_indices = self.remove_listbox.curselection()
        if not selected_indices:
            messagebox.showerror("Error", "Please select at least one account to remove.")
            return
        
        selected_accounts = [self.remove_listbox.get(i) for i in selected_indices]
        if messagebox.askyesno("Confirm", f"Are you sure you want to remove these accounts?\n{', '.join(selected_accounts)}"):
            removed_accounts = []
            for account in selected_accounts:
                if self.pm.remove_account(account):
                    removed_accounts.append(account)
            
            if removed_accounts:
                messagebox.showinfo("Success", f"Successfully removed: {', '.join(removed_accounts)}")
                self.refresh_account_lists()
            else:
                messagebox.showerror("Error", "Failed to remove selected accounts.")

    def change_master_password(self):
        current_password = self.current_master_pass_entry.get()
        new_password = self.new_master_pass_entry.get()
        confirm_password = self.confirm_master_pass_entry.get()

        if not current_password or not new_password or not confirm_password:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        if new_password != confirm_password:
            messagebox.showerror("Error", "New passwords do not match.")
            return

        # Verify current password
        temp_pm = PasswordManager()
        temp_pm.create_key(current_password)
        try:
            temp_pm.load_passwords()
        except:
            messagebox.showerror("Error", "Current password is incorrect.")
            return

        # Change the master password
        self.pm.change_master_password(new_password)
        messagebox.showinfo("Success", "Master password changed successfully.")

        # Clear the entry fields
        self.current_master_pass_entry.delete(0, tk.END)
        self.new_master_pass_entry.delete(0, tk.END)
        self.confirm_master_pass_entry.delete(0, tk.END)
        
    def refresh_account_lists(self):
        accounts = self.pm.list_accounts()
        self.list_search_var.set("")  # Clear search bar
        self.remove_search_var.set("")  # Clear search bar
        self.account_listbox.delete(0, tk.END)
        self.remove_listbox.delete(0, tk.END)
        for account in accounts:
            self.account_listbox.insert(tk.END, account)
            self.remove_listbox.insert(tk.END, account)
        
    def run(self):
        master_password = self.get_master_password()
        if master_password:
            self.pm.create_key(master_password)
            try:
                self.pm.load_passwords()
                self.refresh_account_lists()
                self.master.deiconify()  # Show the main window
                self.center_window(self.master)  # Center the main window again after deiconify
                self.master.protocol("WM_DELETE_WINDOW", self.master.quit)  # Handle window close event
            except:
                messagebox.showerror("Error", "Incorrect master password.")
                self.master.quit()
                sys.exit()
        else:
            self.master.quit()
            sys.exit()

    def get_master_password(self):
        password_window = tk.Toplevel(self.master)
        password_window.title("Master Password")
        password_window.geometry("300x180")
        self.center_window(password_window)
        password_window.protocol("WM_DELETE_WINDOW", lambda: self.cancel_login(password_window))
        password_window.grab_set()  # Make the window modal

        attempts_left = 3
        password_var = tk.StringVar()
        
        message_var = tk.StringVar()
        message_var.set(f"Enter your master password:\n({attempts_left} attempts left)")
        message_label = ttk.Label(password_window, textvariable=message_var)
        message_label.pack(pady=10)

        password_entry = ttk.Entry(password_window, show="*", textvariable=password_var)
        password_entry.pack(pady=5)

        button_frame = ttk.Frame(password_window)
        button_frame.pack(pady=10)

        def submit():
            nonlocal attempts_left
            password = password_var.get()
            
            # Here we're simulating password verification
            # In a real scenario, you'd verify against a stored hash
            temp_pm = PasswordManager()
            temp_pm.create_key(password)
            try:
                temp_pm.load_passwords()
                self.master_password = password
                password_window.destroy
                self.master_password = password
                password_window.destroy()
            except:
                attempts_left -= 1
                if attempts_left > 0:
                    message_var.set(f"Incorrect password.\n({attempts_left} attempts left)")
                    password_entry.delete(0, tk.END)
                else:
                    messagebox.showerror("Error", "Too many incorrect attempts. Exiting.")
                    self.cancel_login(password_window)

        submit_button = ttk.Button(button_frame, text="OK", command=submit)
        submit_button.pack(side=tk.LEFT, padx=5)

        cancel_button = ttk.Button(button_frame, text="Cancel", command=lambda: self.cancel_login(password_window))
        cancel_button.pack(side=tk.LEFT, padx=5)

        password_entry.bind('<Return>', lambda event: submit())

        self.master.wait_window(password_window)
        return getattr(self, 'master_password', None)

    def cancel_login(self, window):
        window.destroy()
        self.master.quit()
        sys.exit()

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    app.run()
    root.mainloop()