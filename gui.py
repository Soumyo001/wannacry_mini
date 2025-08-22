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
        self.iconbitmap(ICON_PATH)
        self.configure(bg='black')
        self.title('Wannacry_mini')
        self.geometry('900x800')
        self.initialize_ui()

    def initialize_ui(self):
        logo_image = Image.open(ICON_PATH).resize((200,200))
        logo_photo = ImageTk.PhotoImage(logo_image)
        frame = tk.Frame(self, bg='black')
        frame.pack(pady=(20,20))

        logo_label = tk.Label(frame, image=logo_photo, bg='black')
        logo_label.image = logo_photo
        logo_label.pack(side=tk.LEFT, padx=(20,10))

    