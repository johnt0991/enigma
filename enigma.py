import string
import hashlib
import platform
import uuid
from datetime import datetime, timedelta
from pytz import timezone
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QLabel, QVBoxLayout, QLineEdit, QPushButton, QTextEdit, QWidget, QHBoxLayout
)
from PyQt5.QtGui import QFont, QColor, QPalette, QClipboard
from PyQt5.QtCore import Qt, QTimer


class KeyGenerator:
    @staticmethod
    def get_machine_serial() -> str:
        """Retrieve a unique identifier for the machine and translate numbers to letters."""
        try:
            serial = str(uuid.getnode())
        except Exception:
            serial = platform.node()

        # Map numbers to letters (A=1, B=2, ..., J=0)
        translation_table = str.maketrans("0123456789", "JABCDEFGHI")
        return serial.translate(translation_table)

    @staticmethod
    def generate_key() -> str:
        """Generate a key based on the current date and a unique UUID."""
        # Step 1: Obtain UUID
        uuid_str = str(uuid.uuid4())

        # Step 2: Repeat the UUID until it's 32 characters long
        repeated_uuid = (uuid_str * 2)[:32]  # This repeats the string and cuts it to 32 characters

        # Step 3: Convert UUID characters to letters (numeric characters to 'JABCDEFGHI')
        translation_table = str.maketrans("0123456789", "JABCDEFGHI")
        converted_str = repeated_uuid.translate(translation_table)

        # Step 4: Calculate the Caesar cipher shift using today's date
        today = datetime.now(timezone("America/Los_Angeles"))
        shift = (today.day + today.month - int(today.strftime("%y"))) % 26  # Ensure a positive shift

        # Step 5: Apply Caesar cipher shift
        shifted_str = KeyGenerator.apply_caesar_cipher(converted_str, shift)

        # Step 6: Encrypt the string with hexadecimal
        hex_encrypted = shifted_str.encode().hex()

        # Return the first 32 characters of the hex encrypted string as the key
        return hex_encrypted[:32]

    @staticmethod
    def apply_caesar_cipher(text: str, shift: int) -> str:
        alphabet = "JABCDEFGHI"  # Custom alphabet mapping
        shifted_text = []
    
        for char in text:
            if char in alphabet:
                current_index = alphabet.index(char)
                new_index = (current_index + shift) % len(alphabet)  # Use modulo to prevent out of range
                shifted_text.append(alphabet[new_index])
            else:
                shifted_text.append(char)  # Keep non-alphabet characters as is
        
        return ''.join(shifted_text)


class EnigmaMachine:
    def __init__(self, key: str):
        # Sanitize the key to include only uppercase letters
        self.key = ''.join([char for char in key.upper() if char.isalpha()])
        self.alphabet = string.ascii_uppercase

    def encrypt(self, message: str) -> str:
        """Encrypt the message using the provided key."""
        message = message.upper()
        encrypted = ''
        
        for i, char in enumerate(message):
            if char in self.alphabet:
                # Map the character using the sanitized key
                key_index = self.alphabet.index(self.key[i % len(self.key)])
                char_index = self.alphabet.index(char)
                encrypted_char = self.alphabet[(char_index + key_index) % 26]  # Wrap around the alphabet
                encrypted += encrypted_char
            else:
                # If it's not a letter, leave it as it is (space, punctuation, etc.)
                encrypted += char
        
        return encrypted

    def decrypt(self, message: str, key: str = None) -> str:
        """Decrypt the message using the provided key."""
        # Sanitize the decryption key to ensure it contains only letters
        decryption_key = ''.join([char for char in (key if key else self.key).upper() if char.isalpha()])
        decrypted = ''
        
        for i, char in enumerate(message):
            if char in self.alphabet:
                # Map the character back using the sanitized key
                key_index = self.alphabet.index(decryption_key[i % len(decryption_key)])
                char_index = self.alphabet.index(char)
                decrypted_char = self.alphabet[(char_index - key_index) % 26]  # Wrap around the alphabet
                decrypted += decrypted_char
            else:
                # If it's not a letter, leave it as it is (space, punctuation, etc.)
                decrypted += char
        
        return decrypted


class EnigmaApp(QMainWindow):
    def __init__(self):
        super().__init__()

        # Generate the unique key for this user
        self.user_key = KeyGenerator.generate_key()
        self.enigma = EnigmaMachine(key=self.user_key)

        # Set up the UI
        self.setWindowTitle("Cyberpunk Enigma Machine")
        self.setGeometry(200, 200, 700, 600)
        self.set_cyberpunk_theme()

        # Main layout
        layout = QVBoxLayout()

        # Display user's unique key with a copy button
        key_layout = QHBoxLayout()
        self.user_key_label = QLabel(f"Your Key: {self.user_key}")
        self.user_key_label.setFont(QFont("Orbitron", 12, QFont.Bold))
        self.user_key_label.setStyleSheet("color: cyan;")
        self.user_key_label.setAlignment(Qt.AlignCenter)
        key_layout.addWidget(self.user_key_label)

        self.copy_button = QPushButton("Copy")
        self.copy_button.setFont(QFont("Orbitron", 10, QFont.Bold))
        self.copy_button.setStyleSheet(
            "background-color: #444444; color: lime; border: 2px solid magenta; padding: 5px;"
        )
        self.copy_button.clicked.connect(self.copy_to_clipboard)
        key_layout.addWidget(self.copy_button)

        layout.addLayout(key_layout)

        # Countdown timer display
        self.timer_label = QLabel("")
        self.timer_label.setFont(QFont("Orbitron", 10))
        self.timer_label.setStyleSheet("color: magenta;")
        self.timer_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.timer_label)

        # Input message box
        self.input_label = QLabel("Enter your message:")
        self.input_label.setFont(QFont("Orbitron", 10))
        self.input_label.setStyleSheet("color: lightgray;")
        layout.addWidget(self.input_label)

        self.input_text = QLineEdit()
        self.input_text.setStyleSheet(
            "background-color: #333333; color: cyan; border: 2px solid magenta; padding: 5px; font-size: 14px;"
        )
        layout.addWidget(self.input_text)

        # Decryption key input box
        self.decrypt_key_label = QLabel("Enter the sender's key for decryption (optional):")
        self.decrypt_key_label.setFont(QFont("Orbitron", 10))
        self.decrypt_key_label.setStyleSheet("color: lightgray;")
        layout.addWidget(self.decrypt_key_label)

        self.decrypt_key_text = QLineEdit()
        self.decrypt_key_text.setStyleSheet(
            "background-color: #333333; color: magenta; border: 2px solid cyan; padding: 5px; font-size: 14px;"
        )
        layout.addWidget(self.decrypt_key_text)

        # Output message box
        self.output_label = QLabel("Result:")
        self.output_label.setFont(QFont("Orbitron", 10))
        self.output_label.setStyleSheet("color: lightgray;")
        layout.addWidget(self.output_label)

        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setStyleSheet(
            "background-color: #333333; color: lime; border: 2px solid cyan; padding: 5px; font-size: 14px;"
        )
        layout.addWidget(self.output_text)

        # Buttons
        self.encrypt_button = QPushButton("Encrypt")
        self.encrypt_button.setFont(QFont("Orbitron", 10, QFont.Bold))
        self.encrypt_button.setStyleSheet(
            "background-color: #444444; color: cyan; border: 2px solid magenta; padding: 10px;"
        )
        self.encrypt_button.clicked.connect(self.encrypt_message)
        layout.addWidget(self.encrypt_button)

        self.decrypt_button = QPushButton("Decrypt")
        self.decrypt_button.setFont(QFont("Orbitron", 10, QFont.Bold))
        self.decrypt_button.setStyleSheet(
            "background-color: #444444; color: magenta; border: 2px solid cyan; padding: 10px;"
        )
        self.decrypt_button.clicked.connect(self.decrypt_message)
        layout.addWidget(self.decrypt_button)

        # Set the layout for the main window
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        # Start the countdown timer
        self.timer_thread()

    def set_cyberpunk_theme(self):
        palette = QPalette()
        palette.setColor(QPalette.Background, QColor("#222222"))
        self.setPalette(palette)

    def timer_thread(self):
        """Start the timer thread and update the countdown label every second."""
        self.update_timer()

    def update_timer(self):
        now = datetime.now(timezone("America/Los_Angeles"))
        remaining_time = timedelta(seconds=60) - timedelta(seconds=now.second)  # Timer to next minute
        self.timer_label.setText(f"Time Remaining: {str(remaining_time)}")
        QTimer.singleShot(1000, self.update_timer)

    def copy_to_clipboard(self):
        """Copy the user's key to the clipboard."""
        clipboard = QApplication.clipboard()
        clipboard.setText(self.user_key)

    def encrypt_message(self):
        """Encrypt the user's input message."""
        message = self.input_text.text()
        encrypted_message = self.enigma.encrypt(message)
        self.output_text.setText(encrypted_message)

    def decrypt_message(self):
        """Decrypt the user's input message."""
        message = self.input_text.text()
        decryption_key = self.decrypt_key_text.text()
        decrypted_message = self.enigma.decrypt(message, key=decryption_key)
        self.output_text.setText(decrypted_message)


def main():
    app = QApplication([]) 
    window = EnigmaApp() 
    window.show()  
    app.exec_()

if __name__ == '__main__':
    main()
