import tkinter as tk
from tkinter import ttk, messagebox
import threading
from checker import analyze_password, check_pwned
from generator import generate_secure, generate_passphrase, generate_pin
from utils import save_report

class SecurePassApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SecurePass") # Updated title
        self.root.geometry("600x720")
        self.root.configure(padx=25, pady=25)
        
        # Define some clean fonts for the UI
        self.font_title = ("Segoe UI", 16, "bold")
        self.font_normal = ("Segoe UI", 11)
        self.font_bold = ("Segoe UI", 11, "bold")
        self.font_small = ("Segoe UI", 9)
        
        self.current_analysis = None
        self.setup_ui()

    def setup_ui(self):
        # Header - Friendly welcome text
        tk.Label(self.root, text="SecurePass", font=self.font_title).pack(anchor="w")
        
        # Input Frame - Where the magic happens
        input_frame = tk.Frame(self.root)
        input_frame.pack(fill="x", pady=(15, 5))
        
        # Trace the input so we can update the UI instantly as they type
        self.pwd_var = tk.StringVar()
        self.pwd_var.trace_add("write", self.on_typing)
        
        self.pwd_entry = tk.Entry(input_frame, textvariable=self.pwd_var, show="*", font=("Consolas", 14), width=35)
        self.pwd_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        # Action Buttons row (Show password, Copy to clipboard)
        actions_frame = tk.Frame(self.root)
        actions_frame.pack(fill="x", pady=5)
        
        self.show_pwd_var = tk.BooleanVar()
        tk.Checkbutton(actions_frame, text="Show", variable=self.show_pwd_var, command=self.toggle_visibility, font=self.font_small).pack(side="left")
        tk.Button(actions_frame, text="Copy to Clipboard", command=self.copy_to_clipboard, font=self.font_small).pack(side="left", padx=10)
        
        # Strength Meter - A visual indicator of how good the password is
        self.canvas = tk.Canvas(self.root, height=12, bg="#e0e0e0", highlightthickness=0)
        self.canvas.pack(fill="x", pady=15)
        self.meter_rect = self.canvas.create_rectangle(0, 0, 0, 12, fill="#d32f2f", outline="")
        
        # Labels for the top-level scores
        self.score_label = tk.Label(self.root, text="Awaiting input...", font=self.font_bold, fg="#555")
        self.score_label.pack(anchor="w")
        self.time_label = tk.Label(self.root, text="", font=self.font_normal)
        self.time_label.pack(anchor="w")
        
        # Dedicated label for the HIBP breach check warnings
        self.hibp_label = tk.Label(self.root, text="", font=self.font_normal, fg="#d32f2f")
        self.hibp_label.pack(anchor="w", pady=(5,0))
        
        # Analysis Panel - The nitty-gritty details
        self.panel = tk.LabelFrame(self.root, text="Analysis Breakdown", font=self.font_bold, padx=15, pady=15)
        self.panel.pack(fill="x", pady=20)
        
        self.len_lbl = tk.Label(self.panel, text="Length: 0/16 recommended", font=self.font_normal)
        self.len_lbl.grid(row=0, column=0, sticky="w", padx=(0, 40), pady=2)
        
        self.up_lbl = tk.Label(self.panel, text="Uppercase: ✗", font=self.font_normal)
        self.up_lbl.grid(row=1, column=0, sticky="w", pady=2)
        
        self.low_lbl = tk.Label(self.panel, text="Lowercase: ✗", font=self.font_normal)
        self.low_lbl.grid(row=2, column=0, sticky="w", pady=2)
        
        self.num_lbl = tk.Label(self.panel, text="Number: ✗", font=self.font_normal)
        self.num_lbl.grid(row=0, column=1, sticky="w", pady=2)
        
        self.sym_lbl = tk.Label(self.panel, text="Symbol: ✗", font=self.font_normal)
        self.sym_lbl.grid(row=1, column=1, sticky="w", pady=2)
        
        self.rep_lbl = tk.Label(self.panel, text="Repeated pattern: ✓ (None)", font=self.font_normal)
        self.rep_lbl.grid(row=2, column=1, sticky="w", pady=2)
        
        # Generator Section - Helps users make better choices
        gen_frame = tk.LabelFrame(self.root, text="Smart Generator", font=self.font_bold, padx=15, pady=15)
        gen_frame.pack(fill="x", pady=5)
        
        self.gen_mode = tk.StringVar(value="Secure")
        modes = [("Very Secure", "Secure"), ("Passphrase (Memorable)", "Passphrase"), ("PIN Code", "PIN")]
        
        for text, mode in modes:
            tk.Radiobutton(gen_frame, text=text, variable=self.gen_mode, value=mode, font=self.font_normal).pack(anchor="w")
            
        tk.Button(gen_frame, text="Generate", command=self.do_generate, font=self.font_bold, bg="#e0f7fa", padx=20).pack(pady=10)
        
        # Save Report
        tk.Button(self.root, text="Export Security Report", command=self.save_report, font=self.font_normal).pack(pady=10, anchor="e")

    def toggle_visibility(self):
        """Swaps the password field between asterisks and plain text."""
        self.pwd_entry.config(show="" if self.show_pwd_var.get() else "*")

    def copy_to_clipboard(self):
        """Quickly copies the generated password so they can use it immediately."""
        pwd = self.pwd_var.get()
        if pwd:
            self.root.clipboard_clear()
            self.root.clipboard_append(pwd)
            messagebox.showinfo("Copied", "Password copied to clipboard!")

    def on_typing(self, *args):
        """Called every time the user types a character."""
        pwd = self.pwd_var.get()
        if not pwd:
            self.reset_ui()
            return
            
        # Get the math and rules checked instantly
        analysis = analyze_password(pwd)
        self.current_analysis = analysis
        self.update_ui(analysis)
        
        # Run the network request in the background so the typing doesn't freeze
        threading.Thread(target=self.async_pwned_check, args=(pwd,), daemon=True).start()

    def async_pwned_check(self, pwd):
        """Background worker for the Have I Been Pwned API."""
        count = check_pwned(pwd)
        
        # Make sure they haven't typed a new password while we were waiting for the network
        if pwd == self.pwd_var.get() and self.current_analysis:
            self.current_analysis['pwned_count'] = count
            # Safely tell the UI thread to update the label
            self.root.after(0, self.update_hibp_ui, count)

    def update_hibp_ui(self, count):
        """Updates the breach warning label on the main thread."""
        if count > 0:
            self.hibp_label.config(text=f"⚠️ This password has appeared in {count:,} known breaches!")
        elif count == 0:
            self.hibp_label.config(text="✓ Password not found in known breaches.", fg="#388e3c")
        else:
            self.hibp_label.config(text="") # Clears it if there's no internet

    def update_ui(self, a):
        """Refreshes all the labels and bars with the latest analysis data."""
        # Update the visual strength meter
        self.canvas.update()
        width = self.canvas.winfo_width()
        fill_width = max(5, int((a['score'] / 100) * width))
        self.canvas.coords(self.meter_rect, 0, 0, fill_width, 12)
        self.canvas.itemconfig(self.meter_rect, fill=a['color'])
        
        # Main top labels
        self.score_label.config(text=f"Estimated strength: {a['entropy']} bits ({a['strength']})", fg=a['color'])
        self.time_label.config(text=f"Estimated brute-force time: {a['crack_time']}")
        self.hibp_label.config(text="Checking breach databases...")
        
        # Helper functions to keep the checkmark logic clean
        def check(val): return "✓" if val else "✗"
        def c_color(val): return "#388e3c" if val else "#d32f2f"
        
        self.len_lbl.config(text=f"Length: {a['length']}/16 recommended", fg=c_color(a['length'] >= 16))
        self.up_lbl.config(text=f"Uppercase: {check(a['has_upper'])}", fg=c_color(a['has_upper']))
        self.low_lbl.config(text=f"Lowercase: {check(a['has_lower'])}", fg=c_color(a['has_lower']))
        self.num_lbl.config(text=f"Number: {check(a['has_digit'])}", fg=c_color(a['has_digit']))
        self.sym_lbl.config(text=f"Symbol: {check(a['has_symbol'])}", fg=c_color(a['has_symbol']))
        
        if a['has_repeat']:
            self.rep_lbl.config(text="Repeated pattern: ✗ (Warning)", fg="#f57c00")
        else:
            self.rep_lbl.config(text="Repeated pattern: ✓ (None)", fg="#388e3c")

    def reset_ui(self):
        """Wipes the UI clean when the entry box is empty."""
        self.canvas.coords(self.meter_rect, 0, 0, 0, 12)
        self.score_label.config(text="Awaiting input...", fg="#555")
        self.time_label.config(text="")
        self.hibp_label.config(text="")
        self.current_analysis = None
        
        self.len_lbl.config(text="Length: 0/16 recommended", fg="#000")
        self.up_lbl.config(text="Uppercase: ✗", fg="#000")
        self.low_lbl.config(text="Lowercase: ✗", fg="#000")
        self.num_lbl.config(text="Number: ✗", fg="#000")
        self.sym_lbl.config(text="Symbol: ✗", fg="#000")
        self.rep_lbl.config(text="Repeated pattern: ✓ (None)", fg="#000")

    def do_generate(self):
        """Grabs a new password based on what radio button they selected."""
        mode = self.gen_mode.get()
        if mode == "Secure":
            pwd = generate_secure()
        elif mode == "Passphrase":
            pwd = generate_passphrase()
        else:
            pwd = generate_pin()
            
        self.pwd_var.set(pwd)
        
        # If the password is hidden, show it automatically so they can see what was generated!
        if not self.show_pwd_var.get():
            self.show_pwd_var.set(True)
            self.toggle_visibility()

    def save_report(self):
        """Takes whatever is on the screen and dumps it to a nice text file."""
        if not self.current_analysis:
            messagebox.showwarning("Warning", "Generate or enter a password first.")
            return
            
        # If the network check was slow, make sure we don't crash
        if 'pwned_count' not in self.current_analysis:
            self.current_analysis['pwned_count'] = -1
            
        path = save_report(self.pwd_var.get(), self.current_analysis)
        messagebox.showinfo("Saved", f"Report saved successfully:\n{path}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SecurePassApp(root)
    root.mainloop()
