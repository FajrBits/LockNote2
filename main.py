import os
import base64
import hashlib
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.filechooser import FileChooserIconView
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class LockNote(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(orientation='vertical', **kwargs)
        
        self.password_input = TextInput(hint_text='Enter Password', password=True, multiline=False)
        self.add_widget(self.password_input)
        
        self.text_input = TextInput(hint_text='Enter text to encrypt/decrypt', multiline=True)
        self.add_widget(self.text_input)
        
        self.encrypt_button = Button(text='Encrypt Text', on_press=self.encrypt_text)
        self.add_widget(self.encrypt_button)
        
        self.decrypt_button = Button(text='Decrypt Text', on_press=self.decrypt_text)
        self.add_widget(self.decrypt_button)
        
        self.file_encrypt_button = Button(text='Encrypt File', on_press=self.choose_file_to_encrypt)
        self.add_widget(self.file_encrypt_button)
        
        self.file_decrypt_button = Button(text='Decrypt File', on_press=self.choose_file_to_decrypt)
        self.add_widget(self.file_decrypt_button)
    
    def derive_key(self, password, salt):
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 1000000, dklen=32)

    def aes_encrypt(self, plaintext, key):
        iv = get_random_bytes(12)  # Nonce for AES-GCM
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return iv + tag + ciphertext  # Return all components needed for decryption
    
    def aes_decrypt(self, encrypted_data, key):
        iv, tag, ciphertext = encrypted_data[:12], encrypted_data[12:28], encrypted_data[28:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        try:
            return cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            return None
    
    def encrypt_text(self, instance):
        password = self.password_input.text.strip()
        text = self.text_input.text.strip()
        if not password or not text:
            self.show_popup('Error', 'Password and text cannot be empty!')
            return
        salt = get_random_bytes(16)
        key = self.derive_key(password, salt)
        encrypted_data = self.aes_encrypt(text.encode(), key)
        self.text_input.text = base64.b64encode(salt + encrypted_data).decode()
        self.show_popup('Success', 'Text encrypted!')
    
    def decrypt_text(self, instance):
        password = self.password_input.text.strip()
        encrypted_text = self.text_input.text.strip()
        if not password or not encrypted_text:
            self.show_popup('Error', 'Password and encrypted text cannot be empty!')
            return
        try:
            encrypted_data = base64.b64decode(encrypted_text)
            salt, encrypted_data = encrypted_data[:16], encrypted_data[16:]
            key = self.derive_key(password, salt)
            decrypted_data = self.aes_decrypt(encrypted_data, key)
            if decrypted_data is None:
                self.show_popup('Error', 'Decryption failed!')
            else:
                self.text_input.text = decrypted_data.decode()
                self.show_popup('Success', 'Text decrypted!')
        except Exception:
            self.show_popup('Error', 'Invalid encrypted text!')
    
    def choose_file_to_encrypt(self, instance):
        self.show_file_chooser(self.encrypt_file)
    
    def choose_file_to_decrypt(self, instance):
        self.show_file_chooser(self.decrypt_file)
    
    def show_file_chooser(self, callback):
        filechooser = FileChooserIconView()
        popup = Popup(title='Select File', content=filechooser, size_hint=(0.9, 0.9))
        
        def on_selection(chooser, selection, touch):
            if selection:
                popup.dismiss()
                callback(selection[0])

        filechooser.bind(on_submit=on_selection)
        popup.open()
    
    def encrypt_file(self, file_path):
        password = self.password_input.text.strip()
        if not password:
            self.show_popup('Error', 'Password cannot be empty!')
            return
        with open(file_path, 'rb') as file:
            plaintext = file.read()
        salt = get_random_bytes(16)
        key = self.derive_key(password, salt)
        encrypted_data = self.aes_encrypt(plaintext, key)
        
        encrypted_path = file_path + ".enc"
        with open(encrypted_path, 'wb') as file:
            file.write(salt + encrypted_data)
        
        os.remove(file_path)
        self.show_popup('Success', f'File encrypted: {encrypted_path}')
    
    def decrypt_file(self, file_path):
        password = self.password_input.text.strip()
        if not password:
            self.show_popup('Error', 'Password cannot be empty!')
            return
        try:
            with open(file_path, 'rb') as file:
                encrypted_data = file.read()
            salt, encrypted_data = encrypted_data[:16], encrypted_data[16:]
            key = self.derive_key(password, salt)
            decrypted_data = self.aes_decrypt(encrypted_data, key)
            if decrypted_data is None:
                self.show_popup('Error', 'Decryption failed!')
                return
            
            decrypted_path = file_path.replace(".enc", "")
            with open(decrypted_path, 'wb') as file:
                file.write(decrypted_data)
            
            os.remove(file_path)
            self.show_popup('Success', f'File decrypted: {decrypted_path}')
        except Exception:
            self.show_popup('Error', 'Decryption failed!')

    def show_popup(self, title, message):
        popup = Popup(title=title, content=Label(text=message), size_hint=(0.8, 0.4))
        popup.open()

class LockNoteApp(App):
    def build(self):
        return LockNote()

if __name__ == '__main__':
    LockNoteApp().run()
