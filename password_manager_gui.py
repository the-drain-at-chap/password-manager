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
from PIL import Image, ImageTk
import io

class PasswordManager:
    def __init__(self):
        self.key = None
        self.password_file = "passwords.json"
        self.password_dict = {}
        self.favorites = set()

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
                data = json.loads(decrypted_data)
                self.password_dict = data.get("passwords", {})
                self.favorites = set(data.get("favorites", []))
        except FileNotFoundError:
            pass

    def save_passwords(self):
        data = {
            "passwords": self.password_dict,
            "favorites": list(self.favorites)
        }
        fernet = Fernet(self.key)
        encrypted_data = fernet.encrypt(json.dumps(data).encode())
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
        return sorted(list(self.password_dict.keys()))

    def change_master_password(self, new_master_password):
        # Decrypt all passwords with the old key
        decrypted_data = self.password_dict

        # Create a new key with the new master password
        self.create_key(new_master_password)

        # Re-encrypt all passwords with the new key
        self.password_dict = decrypted_data
        self.save_passwords()

    def add_to_favorites(self, account_name):
        self.favorites.add(account_name)
        self.save_passwords()

    def remove_from_favorites(self, account_name):
        self.favorites.discard(account_name)
        self.save_passwords()

    def is_favorite(self, account_name):
        return account_name in self.favorites

    def get_favorites(self):
        return sorted([account for account in self.password_dict if account in self.favorites])
    
    def update_password(self, account_name, new_password):
        if account_name in self.password_dict:
            self.password_dict[account_name]['password'] = new_password
            self.save_passwords()
            return True
        return False

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
        # Define Unicode characters for stars
        self.star_empty = "☆"
        self.star_filled = "★"


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
        self.setup_favorites_tab()
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

        # Create Treeview
        self.account_tree = ttk.Treeview(list_frame, columns=('favorite', 'account'), show='headings', selectmode='browse')
        self.account_tree.heading('favorite', text='')
        self.account_tree.heading('account', text='Account')
        self.account_tree.column('favorite', width=30, stretch=tk.NO)
        self.account_tree.column('account', width=200, stretch=tk.YES)
        self.account_tree.pack(expand=True, fill='both', padx=5, pady=5)

        self.account_tree.bind('<ButtonRelease-1>', self.on_account_click)
        
        self.account_info = tk.StringVar()
        ttk.Label(list_frame, textvariable=self.account_info).pack(padx=5, pady=5)
        
        # Button frame
        button_frame = ttk.Frame(list_frame)
        button_frame.pack(expand=True, fill='x', padx=5, pady=5)
        
        # Center buttons within the frame
        button_frame.columnconfigure(0, weight=1)
        button_frame.columnconfigure(2, weight=1)
        
        self.copy_button = ttk.Button(button_frame, text="Copy Password", command=self.copy_password)
        self.copy_button.grid(row=0, column=1, pady=(0, 5))
        self.copy_button.config(state='disabled')
        
        self.generate_button = ttk.Button(button_frame, text="Generate New Password", command=self.generate_new_password)
        self.generate_button.grid(row=1, column=1)
        self.generate_button.config(state='disabled')
    
    def on_account_click(self, event):
        region = self.account_tree.identify("region", event.x, event.y)
        if region == "cell":
            column = self.account_tree.identify_column(event.x)
            item = self.account_tree.identify_row(event.y)
            if item:
                values = self.account_tree.item(item, 'values')
                if column == '#1':  # Star column
                    self.toggle_favorite(values[1])  # values[1] is the account name
                elif column == '#2':  # Account name column
                    self.show_account_info(values[1])
                    self.generate_button.config(state='normal')

    def show_account_info(self, account_name):
        account = self.pm.get_account(account_name)
        if account:
            self.account_info.set(f"Username: {account['username']}\nPassword: {account['password']}")
            self.copy_button.config(state='normal')
        else:
            self.account_info.set("Account information not found.")
            self.copy_button.config(state='disabled')

    def toggle_favorite(self, account_name):
        if self.pm.is_favorite(account_name):
            self.pm.remove_from_favorites(account_name)
        else:
            self.pm.add_to_favorites(account_name)
        self.update_list()
        self.update_favorites()

    def setup_favorites_tab(self):
        favorites_frame = ttk.Frame(self.notebook)
        self.notebook.add(favorites_frame, text="Favorites")
        
        self.favorites_tree = ttk.Treeview(favorites_frame, columns=('account',), show='headings', selectmode='browse')
        self.favorites_tree.heading('account', text='Account')
        self.favorites_tree.column('account', width=200, stretch=tk.YES)
        self.favorites_tree.pack(expand=True, fill='both', padx=5, pady=5)
        self.favorites_tree.bind('<<TreeviewSelect>>', self.on_favorite_select)
        
        self.favorite_info = tk.StringVar()
        ttk.Label(favorites_frame, textvariable=self.favorite_info).pack(padx=5, pady=5)
        
        # Button frame
        button_frame = ttk.Frame(favorites_frame)
        button_frame.pack(expand=True, fill='x', padx=5, pady=5)
        
        # Center buttons within the frame
        button_frame.columnconfigure(0, weight=1)
        button_frame.columnconfigure(2, weight=1)
        
        self.copy_favorite_button = ttk.Button(button_frame, text="Copy Password", command=self.copy_favorite_password)
        self.copy_favorite_button.grid(row=0, column=1, pady=(0, 5))
        self.copy_favorite_button.config(state='disabled')
        
        self.generate_favorite_button = ttk.Button(button_frame, text="Generate New Password", command=self.generate_new_favorite_password)
        self.generate_favorite_button.grid(row=1, column=1)
        self.generate_favorite_button.config(state='disabled')
        
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

        # Create Treeview
        self.remove_tree = ttk.Treeview(remove_frame, columns=('account',), show='headings', selectmode='extended')
        self.remove_tree.heading('account', text='Account')
        self.remove_tree.column('account', width=200, stretch=tk.YES)
        self.remove_tree.pack(expand=True, fill='both', padx=5, pady=5)
        
        remove_button = ttk.Button(remove_frame, text="Remove Selected Accounts", command=self.remove_accounts)
        remove_button.pack(padx=5, pady=5)

    def update_list(self):
        search_term = self.list_search_var.get().lower()
        self.account_tree.delete(*self.account_tree.get_children())
        for account in self.pm.list_accounts():
            if search_term in account.lower():
                star = self.star_filled if self.pm.is_favorite(account) else self.star_empty
                self.account_tree.insert('', 'end', values=(star, account))

    def update_remove_list(self):
        search_term = self.remove_search_var.get().lower()
        self.remove_tree.delete(*self.remove_tree.get_children())
        for account in self.pm.list_accounts():
            if search_term in account.lower():
                self.remove_tree.insert('', 'end', values=(account,))
    
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
        
    def show_new_password(self, password, is_update=False):
        new_window = tk.Toplevel(self.master)
        new_window.title("New Password")
        new_window.geometry("300x150")
        self.center_window(new_window)
        
        action = "Updated" if is_update else "Generated"
        ttk.Label(new_window, text=f"{action} Password:").pack(padx=10, pady=(10, 0))
        ttk.Label(new_window, text=password, font=('TkDefaultFont', 12, 'bold')).pack(padx=10, pady=(0, 10))
        
        def copy_and_close():
            self.master.clipboard_clear()
            self.master.clipboard_append(password)
            self.schedule_clipboard_clear()
            new_window.destroy()
        
        copy_button = ttk.Button(new_window, text="Copy Password", command=copy_and_close)
        copy_button.pack(padx=10, pady=10)
        
    def on_account_select(self, event):
        selection = event.widget.curselection()
        if selection:
            full_text = event.widget.get(selection[0])
            account_name = full_text[2:]  # Remove the star character and space
            account = self.pm.get_account(account_name)
            if account:
                self.account_info.set(f"Username: {account['username']}\nPassword: {account['password']}")
                self.copy_button.config(state='normal')
            else:
                self.account_info.set("Account information not found.")
                self.copy_button.config(state='disabled')

            # Toggle favorite status
            if full_text.startswith(self.star_empty):
                self.pm.add_to_favorites(account_name)
            elif full_text.startswith(self.star_filled):
                self.pm.remove_from_favorites(account_name)
            self.update_list()
            self.update_favorites()

    def update_favorites(self):
        self.favorites_tree.delete(*self.favorites_tree.get_children())
        for account in self.pm.get_favorites():
            self.favorites_tree.insert('', 'end', values=(account,))
        
    def on_favorite_select(self, event):
        selection = self.favorites_tree.selection()
        if selection:
            account_name = self.favorites_tree.item(selection[0], 'values')[0]
            account = self.pm.get_account(account_name)
            if account:
                self.favorite_info.set(f"Username: {account['username']}\nPassword: {account['password']}")
                self.copy_favorite_button.config(state='normal')
                self.generate_favorite_button.config(state='normal')
            else:
                self.favorite_info.set("Account information not found.")
                self.copy_favorite_button.config(state='disabled')
                self.generate_favorite_button.config(state='disabled')

    def copy_favorite_password(self):
        selection = self.favorites_tree.selection()
        if selection:
            account_name = self.favorites_tree.item(selection[0], 'values')[0]
            account = self.pm.get_account(account_name)
            if account:
                self.master.clipboard_clear()
                self.master.clipboard_append(account['password'])
                self.schedule_clipboard_clear()
        
    def copy_password(self):
        selection = self.account_tree.selection()
        if selection:
            item = selection[0]
            account_name = self.account_tree.item(item, 'values')[1]
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
        selected_items = self.remove_tree.selection()
        if not selected_items:
            messagebox.showerror("Error", "Please select at least one account to remove.")
            return
        
        selected_accounts = [self.remove_tree.item(item, 'values')[0] for item in selected_items]
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
        self.update_list()
        self.update_remove_list()
        self.update_favorites()
        
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

    def generate_new_password(self):
        selection = self.account_tree.selection()
        if selection:
            item = selection[0]
            account_name = self.account_tree.item(item, 'values')[1]
            self.generate_and_update_password(account_name)

    def generate_new_favorite_password(self):
        selection = self.favorites_tree.selection()
        if selection:
            account_name = self.favorites_tree.item(selection[0], 'values')[0]
            self.generate_and_update_password(account_name)

    def generate_and_update_password(self, account_name):
        new_password = self.pm.generate_password()
        if self.pm.update_password(account_name, new_password):
            self.show_new_password(new_password, is_update=True)
            self.refresh_account_lists()
            if self.notebook.index(self.notebook.select()) == 1:  # List of Accounts tab
                self.show_account_info(account_name)
            elif self.notebook.index(self.notebook.select()) == 2:  # Favorites tab
                self.on_favorite_select(None)
        else:
            messagebox.showerror("Error", "Failed to update password.")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    app.run()
    root.mainloop()