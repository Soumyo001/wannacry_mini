import sys
import tkinter as tk
from tkinter import messagebox, simpledialog
from tkinter import ttk
from PIL import Image, ImageTk
from datetime import datetime, timedelta
import os

def resource_path(relative_path):
    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)

WALLPAPER_PATH = resource_path('resources/wallpaper.png')
ICON_PATH = resource_path('resources/skull.png')
THANKYOU_PATH = resource_path('resources/thanks.png')

class DecryptorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.iconphoto(False, tk.PhotoImage(file=ICON_PATH))
        self.configure(bg='black')
        self.title('Wannacry_mini')
        self.geometry('900x800')
        self.initialize_ui()

    def initialize_ui(self):
        logo_image = Image.open(ICON_PATH).resize((200,200))
        logo_photo = ImageTk.PhotoImage(logo_image)
        frame = tk.Frame(self, bg='black')
        frame.pack(pady=(20,20))

        logo_label = tk.Label(frame, image=logo_photo, bg='white')
        logo_label.image = logo_photo
        logo_label.pack(side=tk.LEFT, padx=(20,10))

        ransome_note = """OOPS! LOOKS LIKE YOUR FILES ARE ENCRYPTED WITH WANNACRY_MINI T_T (FOR ETERNITY) !! GOOD LUCK :)

        
Just joking. This is a demo project for educational purposes only. 
However, playing with malicious softwares are nowhere close to scary but they can be very harmful. 
[ Users are fully acountable for their actions. ] 
As this is a educational research type-ish project, 
if you encrypt your files with wannacry_mini, then just contact to this email address 
[ "sshhoommoo@gmail.com" ] 
He will try whatever to restore your files.
"""
        ransome_note_label = tk.Text(frame, bg='black', font=('Helvetica', 12), wrap='word', height=16, width=60, borderwidth=0) 
        ransome_note_label.pack(side=tk.LEFT, padx=(10,20))

        ransome_note_label.tag_configure("center_red", justify='center', foreground='red')
        ransome_note_label.insert(tk.END, ransome_note, "center_red")
        ransome_note_label.tag_add("center_red", "1.0", "end")
        ransome_note_label.configure(state='disabled')

        self.setup_key_frame()
        self.setup_log_frame()
        self.setup_progress_frame()

    def setup_key_frame(self):
        key_frame = tk.Frame(self, bg='black')
        key_frame.pack(fill=tk.X, padx=10, pady=(10,5))
        self.key_entry = tk.Entry(key_frame, fg='black', font=('Helvetica', 12), bd=1, relief=tk.FLAT)
        self.key_entry.pack(fill=tk.X, side=tk.LEFT, expand=True, padx=(10, 0), ipady=8)
        tk.Button(key_frame, text="DECRYPT", bg='#d9534f', fg='white', font=('Helvetica', 12),
                  relief=tk.FLAT).pack(side=tk.RIGHT, padx=(10,0))

    def setup_log_frame(self):
        log_frame = tk.Frame(self, bg='black')
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        banner_text = "Welcome to Wannacry_mini T_T"
        banner_label = tk.Label(log_frame, text=banner_text, fg='orange', bg='black', font=('Courier New', 12))
        banner_label.pack(side=tk.TOP, fill=tk.X)
        
        self.log_listbox = tk.Listbox(log_frame, height=6, width=50, bg='black', fg='#00FF00', font=('Courier New', 10))
        self.log_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = tk.Scrollbar(log_frame, orient="vertical", command=self.log_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill="y")
        self.log_listbox.config(yscrollcommand=scrollbar.set)

    def setup_progress_frame(self):
        self.progress_frame = tk.Frame(self, bg='black')
        self.progress_frame.pack(fill=tk.X, padx=10, pady=20)
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Enhanced.Horizontal.TProgressbar", troughcolor='black', background='green', thickness=20)
        self.progress = ttk.Progressbar(self.progress_frame, style="Enhanced.Horizontal.TProgressbar",
                                        orient=tk.HORIZONTAL, length=100, mode='determinate')
        self.progress.pack(fill=tk.X, expand=True)
        self.progress_label = tk.Label(self.progress_frame, text="Decryption Progress: 0%", bg='black', fg='white')
        self.progress_label.pack()

if __name__ == "__main__":
    app = DecryptorApp()
    app.mainloop()