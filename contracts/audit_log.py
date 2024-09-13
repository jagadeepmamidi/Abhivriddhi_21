import json
from web3 import Web3

import os

# Blockchain connection: directly hardcoding the URL for simplicity
import json
from web3 import Web3

# Blockchain connection: directly hardcoding the URL for simplicity
blockchain_url = "http://127.0.0.1:7545"  # Ensure this matches your Ganache or node setup
web3 = Web3(Web3.HTTPProvider(blockchain_url))

# Check if the connection is successful
print(f"Connecting to blockchain at {blockchain_url}...")
if not web3.is_connected():
    raise ConnectionError(f"Failed to connect to blockchain at {blockchain_url}")
else:
    print("Successfully connected to the blockchain.")

# Setting up Ganache test account (replace with actual accounts from Ganache)
sender_account = web3.eth.accounts[0]
web3.eth.default_account = sender_account

# Rest of your code remains the same...

# Load the compiled contract ABI and Bytecode
compiled_contract_path = os.path.join(os.path.dirname(__file__), '../build/contracts/AuditLog.json')
with open(compiled_contract_path, 'r') as file:
    audit_contract_json = json.load(file)
    audit_contract_abi = audit_contract_json['abi']

# Deployed contract address: Replace this with the address of the deployed contract on your Ganache network
contract_address = "0xe533C48F212a4fb0C67F6B31A917699D2E315FcE"  # Update with actual address
contract = web3.eth.contract(address=contract_address, abi=audit_contract_abi)

# Function to add an audit log entry to the blockchain
def add_audit_log(user, data_hash, action, timestamp):
    """
    Adds an audit log entry to the blockchain.
    :param user: Username
    :param data_hash: Hash of the redacted data
    :param action: Action performed (e.g., 'redact')
    :param timestamp: Unix timestamp
    """
    print(f"Adding audit log - User: {user}, Hash: {data_hash}, Action: {action}, Timestamp: {timestamp}")
    
    def add_audit_log(user: str, data_hash: str, action: str, timestamp: str):
        try:
        # Call the smart contract function to add a log
            tx_hash = contract.functions.addLog(data_hash, action, timestamp).transact({'from': user})
        
        # Wait for transaction receipt
            receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
        
            st.info(f"Log added to blockchain. Transaction Hash: {tx_hash.hex()}")
        
        # Check for events
            log_created_event = contract.events.LogCreated().process_receipt(receipt)
            if log_created_event:
                st.success("Event emitted successfully")
                st.json(log_created_event)
            else:
                st.warning("No event was emitted.")
        
            return True
    
        except ValueError as e:
            st.error(f"Invalid input: {e}")
        except Exception as e:
            st.error(f"Error adding log to blockchain: {e}")
    
    return False

# Example usage (can be triggered from your main app):
if __name__ == "__main__":
    user = "user1"
    data_hash = "0x123456789abcdef"  # Replace with actual hash from redacted data
    action = "redact"
    timestamp = 1694457600  # Example timestamp (use actual current timestamp)
    
    add_audit_log(user, data_hash, action, timestamp)
