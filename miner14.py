import time
import json
import asyncio
import hashlib
import logging
import sqlite3
from typing import Dict, List
from aiohttp import web
from nacl.public import PrivateKey
from nacl.signing import SigningKey

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

    def add_block(self, block: Block, signature: str, public_key: bytes):
        if self.is_block_valid(block) and self.verify_block_signature(block, signature, public_key):
            self.chain.append(block)
            self.pending_transactions = []
            logging.info(f"Block #{block.block_index} added to the chain.")
        else:
            logging.warning(f"Block #{block.block_index} is invalid or signature is incorrect.")

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
        if self.validate_transaction(transaction):
            self.pending_transactions.append(transaction)
            logging.info(f"Transaction added: {transaction}")
        else:
            logging.warning(f"Invalid transaction: {transaction}")

    def validate_transaction(self, transaction: Dict) -> bool:
        sender_balance = self.get_balance(transaction["sender"])
        return sender_balance >= transaction["amount"]

    def validate_transactions(self, transactions: List[Dict]) -> bool:
        for transaction in transactions:
            if not self.validate_transaction(transaction):
                return False
        return True

    def get_balance(self, address: str) -> int:
        balance = 0
        for block in self.chain:
            for transaction in block.transactions:
                if transaction["receiver"] == address:
                    balance += transaction["amount"]
                if transaction["sender"] == address:
                    balance -= transaction["amount"]
        return balance

    def sign_block(self, block: Block, private_key: bytes) -> str:
        signing_key = SigningKey(private_key)
        block_data = json.dumps(block.to_dict(), sort_keys=True).encode()
        signed_block = signing_key.sign(block_data)
        return signed_block.signature.hex()

    def verify_block_signature(self, block: Block, signature: str, public_key: bytes) -> bool:
        verify_key = SigningKey(public_key).verify_key
        block_data = json.dumps(block.to_dict(), sort_keys=True).encode()
        try:
            verify_key.verify(block_data, bytes.fromhex(signature))
            return True
        except:
            return False

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

class SmartContract:
    def __init__(self, contract_file: str):
        try:
            with open(contract_file, "r") as file:
                self.contracts = json.load(file)
            logging.info(f"Loaded contracts from {contract_file}")
        except Exception as e:
            logging.error(f"Error loading contracts: {e}")
            self.contracts = {}

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
        # Здесь можно добавить безопасное выполнение кода (например, через ограниченный интерпретатор)
        return True  # Заглушка

class Miner:
    def __init__(self, config: Dict):
        self.port = int(config.get("port", 5001))
        self.miner_ip = config.get("ip", "0.0.0.0")
        self.nodes_file = config.get("nodes_file", "nodes.json")
        self.known_nodes = self.load_known_nodes()

        self.private_key = PrivateKey.generate()
        self.public_key = self.private_key.public_key

        self.blockchain = Blockchain()
        self.smart_contract = SmartContract("contracts.json")
        self.db_connection = sqlite3.connect("blockchain.db")
        self.init_db()

        if not self.blockchain.chain:
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

    async def handle_transaction(self, request):
        data = await request.json()
        transaction = data.get("transaction")
        signature = data.get("signature")

        try:
            signing_key = SigningKey(self.public_key.encode())
            signing_key.verify(json.dumps(transaction).encode(), bytes.fromhex(signature))
            logging.info("Transaction signature verified.")
        except Exception as e:
            logging.error(f"Invalid transaction signature: {e}")
            return web.json_response({"status": "error", "message": "Invalid signature"}, status=400)

        self.blockchain.add_transaction(transaction)
        return web.json_response({"status": "success"})

    async def handle_balance(self, request):
        address = request.match_info["address"]
        balance = self.blockchain.get_balance(address)
        return web.json_response({"balance": balance})

    async def handle_chain_request(self, request):
        chain_data = [block.to_dict() for block in self.blockchain.chain]
        return web.json_response(chain_data)

    async def handle_update_chain(self, request):
        new_chain = await request.json()
        if self.blockchain.is_chain_valid(new_chain):
            self.blockchain.replace_chain(new_chain)
            logging.info("Chain updated from another node.")
            return web.json_response({"status": "success"})
        else:
            logging.warning("Received invalid chain.")
            return web.json_response({"status": "error", "message": "Invalid chain"}, status=400)

    async def fetch_chain_from_node(self, node: str) -> List[Dict]:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://{node}/chain") as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        logging.warning(f"Failed to fetch chain from {node}: {response.status}")
        except Exception as e:
            logging.error(f"Error fetching chain from {node}: {e}")
        return None

    async def broadcast_chain(self, chain: List[Dict]):
        for node in self.known_nodes:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(f"http://{node}/update_chain", json=chain) as response:
                        if response.status == 200:
                            logging.info(f"Chain broadcasted to {node} successfully.")
                        else:
                            logging.warning(f"Failed to broadcast chain to {node}: {response.status}")
            except Exception as e:
                logging.error(f"Error broadcasting chain to {node}: {e}")

    async def sync_blockchain_periodically(self):
        while True:
            await asyncio.sleep(60)
            logging.info("Syncing blockchain with other nodes...")

            longest_chain = None
            max_length = len(self.blockchain.chain)

            for node in self.known_nodes:
                chain = await self.fetch_chain_from_node(node)
                if chain and len(chain) > max_length and self.blockchain.is_chain_valid(chain):
                    longest_chain = chain
                    max_length = len(chain)

            if longest_chain:
                self.blockchain.replace_chain(longest_chain)
                logging.info(f"Chain replaced with a longer one from another node. New length: {max_length}")
            else:
                logging.info("No longer valid chain found.")

    async def start_server(self):
        app = web.Application()
        app.router.add_post("/transaction", self.handle_transaction)
        app.router.add_get("/balance/{address}", self.handle_balance)
        app.router.add_get("/chain", self.handle_chain_request)
        app.router.add_post("/update_chain", self.handle_update_chain)

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, self.miner_ip, self.port)
        await site.start()
        logging.info(f"Server started at http://{self.miner_ip}:{self.port}")

        await self.sync_blockchain_periodically()

    def mine_block(self):
        last_block = self.blockchain.get_last_block()
        new_block = Block(
            block_index=last_block.block_index + 1,
            previous_hash=last_block.hash,
            timestamp=time.time(),
            transactions=self.blockchain.pending_transactions,
            nonce=0
        )

        if self.blockchain.validate_transactions(new_block.transactions):
            signature = self.blockchain.sign_block(new_block, self.private_key.encode())
            self.blockchain.add_block(new_block, signature, self.public_key.encode())
            logging.info(f"Block #{new_block.block_index} mined and added to the chain.")
        else:
            logging.warning(f"Block #{new_block.block_index} contains invalid transactions.")

async def main():
    config = load_config()
    miner = Miner(config)
    await miner.start_server()

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

if __name__ == "__main__":
    asyncio.run(main())