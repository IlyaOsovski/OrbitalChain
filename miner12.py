import time
import json
import asyncio
import hashlib
import logging
import sqlite3
from typing import Dict, List
from stun import get_ip_info
from nacl.public import PrivateKey, Box
from nacl.utils import EncryptedMessage

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

CONFIG_FILE = "config.json"

class Block:
    def __init__(self, block_index: int, previous_hash: str, timestamp: float, transactions: List[Dict], nonce: int = 0):
        self.block_index = block_index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.transactions = transactions
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self) -> str:
        block_data = f"{self.block_index}{self.previous_hash}{self.timestamp}{json.dumps(self.transactions)}{self.nonce}"
        return hashlib.sha256(block_data.encode()).hexdigest()

    def to_dict(self) -> Dict:
        return {
            "block_index": self.block_index,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "nonce": self.nonce,
            "hash": self.hash
        }

class Blockchain:
    def __init__(self):
        self.chain = []
        self.pending_transactions = []

    def create_genesis_block(self):
        genesis_block = Block(0, "0", time.time(), [])
        self.chain.append(genesis_block)

    def get_last_block(self) -> Block:
        return self.chain[-1]

    def add_block(self, block: Block):
        if self.is_block_valid(block):
            self.chain.append(block)
            self.pending_transactions = []
            logging.info(f"Block #{block.block_index} added to the chain.")
        else:
            logging.warning(f"Block #{block.block_index} is invalid.")

    def is_block_valid(self, block: Block) -> bool:
        last_block = self.get_last_block()
        if block.block_index != last_block.block_index + 1:
            return False
        if block.previous_hash != last_block.hash:
            return False
        if block.hash != block.calculate_hash():
            return False
        return True

    def add_transaction(self, transaction: Dict):
        self.pending_transactions.append(transaction)
        logging.info(f"Transaction added: {transaction}")

    def mine_block(self, miner_address: str):
        last_block = self.get_last_block()
        new_block = Block(
            block_index=last_block.block_index + 1,
            previous_hash=last_block.hash,
            timestamp=time.time(),
            transactions=self.pending_transactions,
            nonce=0
        )
        new_block.nonce = self.proof_of_work(new_block)
        self.add_block(new_block)

    def proof_of_work(self, block: Block, difficulty: int = 4) -> int:
        target = '0' * difficulty
        nonce = 0
        while True:
            block.nonce = nonce
            block_hash = block.calculate_hash()
            if block_hash.startswith(target):
                return nonce
            nonce += 1

    def replace_chain(self, new_chain: List[Dict]):
        if len(new_chain) > len(self.chain) and self.is_chain_valid(new_chain):
            self.chain = [Block(**{k: v for k, v in block.items() if k != 'hash'}) for block in new_chain]
            logging.info("Chain replaced with a longer one.")
        else:
            logging.warning("Chain not replaced.")

    def is_chain_valid(self, chain: List[Dict]) -> bool:
        for i in range(1, len(chain)):
            current_block = chain[i]
            previous_block = chain[i - 1]
            if current_block["previous_hash"] != previous_block["hash"]:
                return False
            if current_block["hash"] != Block(**current_block).calculate_hash():
                return False
        return True

    def get_balance(self, address: str) -> int:
        balance = {}
        for block in self.chain:
            for transaction in block.transactions:
                balance[transaction["receiver"]] = balance.get(transaction["receiver"], 0) + transaction["amount"]
                balance[transaction["sender"]] = balance.get(transaction["sender"], 0) - transaction["amount"]
        return balance.get(address, 0)

    def validate_transaction(self, transaction: Dict) -> bool:
        sender_balance = self.get_balance(transaction["sender"])
        new_balance = sender_balance - transaction["amount"]
        return new_balance >= 0

class SmartContract:
    def __init__(self, contract_file: str):
        with open(contract_file, "r") as file:
            self.contracts = json.load(file)

    def execute(self, contract_name: str, transaction: Dict):
        contract = self.contracts.get(contract_name)
        if not contract:
            logging.error(f"Contract '{contract_name}' not found.")
            return

        if contract["code"] == "transfer":
            sender = transaction.get("sender")
            receiver = transaction.get("receiver")
            amount = transaction.get("amount")
            if self.validate_conditions(contract["conditions"], transaction):
                logging.info(f"Smart Contract: Transfer {amount} tokens from {sender} to {receiver}.")
            else:
                logging.error("Contract conditions not met.")

    def validate_conditions(self, conditions: List[str], transaction: Dict) -> bool:
        for condition in conditions:
            if not self.safe_eval(condition, transaction):
                return False
        return True

    def safe_eval(self, condition: str, transaction: Dict) -> bool:
        pass

class SecureConnection:
    def __init__(self, private_key: PrivateKey, peer_public_key: bytes):
        try:
            self.private_key = private_key
            self.peer_public_key = PrivateKey(peer_public_key).public_key
            self.box = Box(self.private_key, self.peer_public_key)
        except Exception as e:
            logging.error(f"Error initializing secure connection: {e}")
            raise

    def encrypt_message(self, message: dict) -> bytes:
        message_bytes = json.dumps(message).encode()
        encrypted = self.box.encrypt(message_bytes)
        return encrypted

    def decrypt_message(self, encrypted: bytes) -> dict:
        decrypted = self.box.decrypt(encrypted)
        return json.loads(decrypted.decode())

class Miner:
    def __init__(self, config: Dict):
        self.port = int(config.get("port", 5001))
        self.miner_ip = config.get("ip", "0.0.0.0")
        self.nodes_file = config.get("nodes_file", "nodes.json")
        self.difficulty = int(config.get("difficulty", 4))
        self.known_nodes = self.load_known_nodes()

        self.private_key = PrivateKey.generate()
        self.public_key = self.private_key.public_key

        self.blockchain = Blockchain()
        self.db_connection = sqlite3.connect("blockchain.db")
        self.init_db()

        # Загрузка блокчейна из базы данных при инициализации
        self.blockchain.chain = self.retrieve_all_blocks_from_db()
        if not self.blockchain.chain:  # Если база данных пуста, создаем генезис-блок
            self.blockchain.create_genesis_block()

        logging.info(f"Initialization of Miner: IP = {self.miner_ip}, Port = {self.port}")

    def load_known_nodes(self):
        try:
            with open(self.nodes_file, "r") as file:
                return set(json.load(file))
        except (FileNotFoundError, json.JSONDecodeError):
            logging.warning(f"Error loading known nodes from {self.nodes_file}. Returning an empty set.")
            return set()

    def init_db(self):
        cursor = self.db_connection.cursor()
        cursor.execute("""
                       CREATE TABLE IF NOT EXISTS blocks (
                       block_index INTEGER PRIMARY KEY,  
                       previous_hash TEXT,
                       timestamp REAL,
                       transactions TEXT,
                       nonce INTEGER,
                       hash TEXT
                       )
                       """)
        self.db_connection.commit()

    def save_block_to_db(self, block: Block):
        """Сохраняет блок в базу данных."""
        cursor = self.db_connection.cursor()
        cursor.execute(
            "INSERT INTO blocks VALUES (?, ?, ?, ?, ?, ?)",
            (
                block.block_index, 
                block.previous_hash, 
                block.timestamp, 
                json.dumps(block.transactions), 
                block.nonce, 
                block.hash
            )
        )
        self.db_connection.commit()

    def retrieve_all_blocks_from_db(self) -> List[Block]:
        """Извлекает все блоки из базы данных."""
        cursor = self.db_connection.cursor()
        cursor.execute("SELECT * FROM blocks")
        blocks_data = cursor.fetchall()
        return [
            Block(
                block_index=row[0],
                previous_hash=row[1],
                timestamp=row[2],
                transactions=json.loads(row[3]),
                nonce=row[4]
            ) for row in blocks_data
        ]

    def add_block(self, block: Block):
        """Добавляет блок в блокчейн и сохраняет его в базу данных."""
        if self.blockchain.is_block_valid(block):
            self.blockchain.add_block(block)
            self.save_block_to_db(block)
            logging.info(f"Block #{block.block_index} added to the chain and database.")
        else:
            logging.warning(f"Block #{block.block_index} is invalid.")

    async def get_external_ip(self):
        try:
            external_ip, external_port = get_ip_info()
            logging.info(f"External IP address: {external_ip}, Port: {external_port}")
            return external_ip, external_port
        except Exception as e:
            logging.error(f"Error determining external IP: {e}")
            return None, None

    async def listen_for_blocks(self):
        try:
            server = await asyncio.start_server(
                self.handle_connection,
                self.miner_ip,
                self.port
            )
            async with server:
                logging.info("Server is running and listening for connections")
                await server.serve_forever()
        except Exception as e:
            logging.error(f"Error starting the server: {e}")

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info('peername')
        logging.info(f"Connection established with {addr}")

        try:
            peer_public_key_bytes = await reader.read(1024)
            peer_public_key = PrivateKey(peer_public_key_bytes).public_key

            writer.write(self.public_key.encode())
            await writer.drain()

            secure_conn = SecureConnection(self.private_key, peer_public_key)

            encrypted_data = await reader.read(4096)
            message = secure_conn.decrypt_message(encrypted_data)

            await self.handle_incoming_data(message, addr)
        except Exception as e:
            logging.error(f"Error processing data: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def handle_incoming_data(self, message: Dict, addr: tuple):
        try:
            if message.get("type") == "block":
                block_data = message.get("data")
                block = Block(
                    block_index=block_data["block_index"],
                    previous_hash=block_data["previous_hash"],
                    timestamp=block_data["timestamp"],
                    transactions=block_data["transactions"],
                    nonce=block_data["nonce"]
                )
                self.add_block(block)
            elif message.get("type") == "transaction":
                transaction = message.get("data")
                self.blockchain.add_transaction(transaction)
            elif message.get("type") == "sync_request":
                await self.send_blockchain(addr)
        except Exception as e:
            logging.error(f"Error: {e}")

    async def send_blockchain(self, addr: tuple):
        blockchain_data = [block.to_dict() for block in self.blockchain.chain]
        message = {"type": "blockchain", "data": blockchain_data}
        await self.send_message(message, addr)

    async def send_message(self, message: Dict, addr: tuple):
        try:
            reader, writer = await asyncio.open_connection(addr[0], addr[1])

            writer.write(self.public_key.encode())
            await writer.drain()

            peer_public_key_bytes = await reader.read(1024)
            peer_public_key = PrivateKey(peer_public_key_bytes).public_key

            secure_conn = SecureConnection(self.private_key, peer_public_key)

            encrypted_message = secure_conn.encrypt_message(message)
            writer.write(encrypted_message)
            await writer.drain()

            writer.close()
            await writer.wait_closed()
        except Exception as e:
            logging.error(f"Error sending message: {e}")

    async def sync_blockchain(self):
        for node in self.known_nodes:
            await self.send_message({"type": "sync_request"}, node)

    async def broadcast_block(self, block: Block):
        for node in self.known_nodes:
            await self.send_message({"type": "block", "data": block.to_dict()}, node)

    async def broadcast_transaction(self, transaction: Dict):
        for node in self.known_nodes:
            await self.send_message({"type": "transaction", "data": transaction}, node)

    async def sync_blockchain_periodically(self):
        while True:
            await asyncio.sleep(60)
            await self.sync_blockchain()

def load_config() -> Dict:
    try:
        with open(CONFIG_FILE, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        logging.error(f"Configuration file {CONFIG_FILE} not found.")
        return {}
    except json.JSONDecodeError:
        logging.error(f"Error decoding JSON in file {CONFIG_FILE}.")
        return {}

async def main():
    config = load_config()
    miner = Miner(config)
    
    listen_task = asyncio.create_task(miner.listen_for_blocks())
    
    sync_task = asyncio.create_task(miner.sync_blockchain_periodically())
    
    await asyncio.gather(listen_task, sync_task)

if __name__ == "__main__":
    asyncio.run(main())