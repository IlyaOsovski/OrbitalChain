import json
import os
from typing import Dict
from nacl.public import PrivateKey
from nacl.signing import SigningKey
from bip32utils import BIP32Key
from mnemonic import Mnemonic
from kivy.lang import Builder
from kivy.uix.screenmanager import Screen, ScreenManager
from kivymd.app import MDApp
from kivymd.uix.button import MDRaisedButton
from kivymd.uix.card import MDCard
from kivymd.uix.dialog import MDDialog
from kivymd.uix.label import MDLabel
from kivymd.uix.textfield import MDTextField
from kivy.core.window import Window

# Константа для имени файла кошелька
WALLET_FILE = "wallet.json"

# Загрузка KV-файла для интерфейса
Builder.load_string('''
<MainScreen>:
    BoxLayout:
        orientation: 'vertical'
        padding: 20
        spacing: 20
        md_bg_color: 0.95, 0.95, 0.95, 1  # Светло-серый фон

        MDLabel:
            text: "ImperiumVault (IVT)"
            font_style: "H6"
            halign: "center"
            theme_text_color: "Custom"
            text_color: 0.2, 0.2, 0.2, 1  # Темно-серый
            size_hint_y: None
            height: "40dp"

        MDCard:
            orientation: 'vertical'
            padding: 20
            spacing: 10
            size_hint: 1, None
            height: "120dp"
            md_bg_color: 1, 1, 1, 1  # Белый фон карточки
            elevation: 4

            MDLabel:
                id: balance_label
                text: "Balance: 0 IVT"
                halign: "center"
                font_style: "Body1"
                theme_text_color: "Custom"
                text_color: 0.2, 0.2, 0.2, 1  # Темно-серый

        MDRaisedButton:
            text: "Send Transaction"
            on_press: root.manager.current = 'send_screen'
            md_bg_color: 0.1, 0.5, 0.8, 1  # Приглушенный синий
            theme_text_color: "Custom"
            text_color: 1, 1, 1, 1  # Белый
            size_hint_y: None
            height: "48dp"

        MDRaisedButton:
            text: "Show Seed Phrase"
            on_press: root.show_seed_phrase()
            md_bg_color: 0.3, 0.3, 0.3, 1  # Темно-серый
            theme_text_color: "Custom"
            text_color: 1, 1, 1, 1  # Белый
            size_hint_y: None
            height: "48dp"

<SendScreen>:
    BoxLayout:
        orientation: 'vertical'
        padding: 20
        spacing: 20
        md_bg_color: 0.95, 0.95, 0.95, 1  # Светло-серый фон

        MDTextField:
            id: receiver_input
            hint_text: "Receiver Address"
            mode: "rectangle"
            color_mode: "custom"
            line_color_normal: 0.1, 0.5, 0.8, 1  # Приглушенный синий
            line_color_focus: 0.2, 0.6, 1, 1  # Яркий синий
            size_hint_y: None
            height: "48dp"

        MDTextField:
            id: amount_input
            hint_text: "Amount"
            mode: "rectangle"
            color_mode: "custom"
            line_color_normal: 0.1, 0.5, 0.8, 1  # Приглушенный синий
            line_color_focus: 0.2, 0.6, 1, 1  # Яркий синий
            size_hint_y: None
            height: "48dp"

        MDRaisedButton:
            text: "Send"
            on_press: root.send_transaction()
            md_bg_color: 0.1, 0.5, 0.8, 1  # Приглушенный синий
            theme_text_color: "Custom"
            text_color: 1, 1, 1, 1  # Белый
            size_hint_y: None
            height: "48dp"

        MDRaisedButton:
            text: "Back"
            on_press: root.manager.current = 'main_screen'
            md_bg_color: 0.3, 0.3, 0.3, 1  # Темно-серый
            theme_text_color: "Custom"
            text_color: 1, 1, 1, 1  # Белый
            size_hint_y: None
            height: "48dp"

<RestoreScreen>:
    BoxLayout:
        orientation: 'vertical'
        padding: 20
        spacing: 20
        md_bg_color: 0.95, 0.95, 0.95, 1  # Светло-серый фон

        MDTextField:
            id: seed_input
            hint_text: "Enter Seed Phrase"
            mode: "rectangle"
            color_mode: "custom"
            line_color_normal: 0.1, 0.5, 0.8, 1  # Приглушенный синий
            line_color_focus: 0.2, 0.6, 1, 1  # Яркий синий
            multiline: True
            size_hint_y: None
            height: "100dp"

        MDRaisedButton:
            text: "Restore Wallet"
            on_press: root.restore_wallet()
            md_bg_color: 0.1, 0.5, 0.8, 1  # Приглушенный синий
            theme_text_color: "Custom"
            text_color: 1, 1, 1, 1  # Белый
            size_hint_y: None
            height: "48dp"

        MDRaisedButton:
            text: "Back"
            on_press: root.manager.current = 'main_screen'
            md_bg_color: 0.3, 0.3, 0.3, 1  # Темно-серый
            theme_text_color: "Custom"
            text_color: 1, 1, 1, 1  # Белый
            size_hint_y: None
            height: "48dp"
''')

class Wallet:
    """Класс для управления крипто кошельком."""

    def __init__(self, seed_phrase: str = None):
        """
        Инициализация кошелька.
        Если передан seed_phrase, восстанавливаем кошелек из него.
        Иначе создаем новый кошелек.
        """
        if seed_phrase:
            # Восстанавливаем кошелек из seed_phrase
            self.seed_phrase = seed_phrase
        else:
            # Создаем новый кошелек
            mnemo = Mnemonic("english")
            self.seed_phrase = mnemo.generate(strength=128)  # Генерируем seed-фразу

        # Генерируем ключи из seed-фразы
        seed = Mnemonic.to_seed(self.seed_phrase)
        master_key = BIP32Key.fromEntropy(seed)
        self.private_key = PrivateKey(master_key.PrivateKey())
        self.public_key = self.private_key.public_key
        self.signing_key = SigningKey(self.private_key.encode())

    def get_address(self) -> str:
        """Возвращает адрес кошелька (публичный ключ)."""
        return self.public_key.encode().hex()

    def get_signing_key(self) -> str:
        """Возвращает signing_key в виде строки для сохранения."""
        return self.signing_key.encode().hex()

    def get_seed_phrase(self) -> str:
        """Возвращает seed-фразу."""
        return self.seed_phrase

    def sign_transaction(self, transaction: Dict) -> Dict:
        """Подписывает транзакцию."""
        transaction_data = json.dumps(transaction).encode()
        signature = self.signing_key.sign(transaction_data)
        return {
            "transaction": transaction,
            "signature": signature.signature.hex()
        }

def save_wallet(wallet: Wallet):
    """Сохраняет данные кошелька в файл."""
    wallet_data = {
        "address": wallet.get_address(),
        "signing_key": wallet.get_signing_key(),
        "seed_phrase": wallet.get_seed_phrase()
    }
    with open(WALLET_FILE, "w") as f:
        json.dump(wallet_data, f)
    print(f"Wallet saved to {WALLET_FILE}")

def load_wallet() -> Wallet:
    """Загружает кошелек из файла, если он существует."""
    if os.path.exists(WALLET_FILE):
        with open(WALLET_FILE, "r") as f:
            wallet_data = json.load(f)
        print(f"Wallet loaded from {WALLET_FILE}")
        return Wallet(seed_phrase=wallet_data["seed_phrase"])
    return None

class MainScreen(Screen):
    def show_seed_phrase(self):
        """Показывает seed-фразу во всплывающем окне."""
        wallet = MDApp.get_running_app().wallet
        dialog = MDDialog(
            title="Your Seed Phrase",
            text=wallet.get_seed_phrase(),
            size_hint=(0.8, 0.4)
        )
        dialog.open()

class SendScreen(Screen):
    def send_transaction(self):
        """Отправляет транзакцию."""
        wallet = MDApp.get_running_app().wallet
        receiver = self.ids.receiver_input.text
        amount = self.ids.amount_input.text

        if not receiver or not amount:
            self.show_error("Please enter receiver and amount.")
            return

        try:
            amount = int(amount)
            transaction = {
                "sender": wallet.get_address(),
                "receiver": receiver,
                "amount": amount
            }
            signed_transaction = wallet.sign_transaction(transaction)
            self.show_success(f"Transaction sent: {signed_transaction}")
        except ValueError:
            self.show_error("Invalid amount. Please enter a valid integer.")

    def show_error(self, message: str):
        """Показывает ошибку во всплывающем окне."""
        dialog = MDDialog(
            title="Error",
            text=message,
            size_hint=(0.8, 0.4)
        )
        dialog.open()

    def show_success(self, message: str):
        """Показывает успешное сообщение во всплывающем окне."""
        dialog = MDDialog(
            title="Success",
            text=message,
            size_hint=(0.8, 0.4)
        )
        dialog.open()

class RestoreScreen(Screen):
    def restore_wallet(self):
        """Восстанавливает кошелек из seed-фразы."""
        seed_phrase = self.ids.seed_input.text.strip()
        if seed_phrase:
            app = MDApp.get_running_app()
            app.wallet = Wallet(seed_phrase=seed_phrase)
            save_wallet(app.wallet)
            self.manager.current = 'main_screen'
        else:
            self.show_error("Please enter a valid seed phrase.")

    def show_error(self, message: str):
        """Показывает ошибку во всплывающем окне."""
        dialog = MDDialog(
            title="Error",
            text=message,
            size_hint=(0.8, 0.4)
        )
        dialog.open()

class WalletApp(MDApp):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.wallet = load_wallet()
        if not self.wallet:
            self.wallet = Wallet()
            save_wallet(self.wallet)

    def build(self):
        self.theme_cls.primary_palette = "Blue"  # Цветовая схема
        sm = ScreenManager()
        sm.add_widget(MainScreen(name='main_screen'))
        sm.add_widget(SendScreen(name='send_screen'))
        sm.add_widget(RestoreScreen(name='restore_screen'))
        return sm

if __name__ == "__main__":
    WalletApp().run()