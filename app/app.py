import streamlit as st
import os
import json
import logging
from web3 import Web3
import json
import streamlit as st
from docx import Document
from pptx import Presentation


logging.basicConfig(
    filename="data_protection_tool.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

blockchain_url = (
    "http://127.0.0.1:7545"  # Ensure this matches your Ganache or node setup
)
web3 = Web3(Web3.HTTPProvider(blockchain_url))

contract_address = "0xC102485B17DFb516bE9A2a07c78C50102E499F5D"  # Replace with your deployed contract address

# Use the user's suggested approach
compiled_contract_path = os.path.join(
    os.path.dirname(__file__), "../build/contracts/AuditLog.json"
)
with open(compiled_contract_path, "r") as file:
    audit_contract_json = json.load(file)
    audit_contract_abi = audit_contract_json["abi"]


contract = web3.eth.contract(address=contract_address, abi=audit_contract_abi)

# Set default account
web3.eth.default_account = web3.eth.accounts[0]


def get_audit_logs():
    """
    Retrieve all audit logs from the blockchain.
    """
    try:
        logs = contract.functions.getLogs().call()
        for log in logs:
            print(
                f"User: {log[0]}, Hash: {log[1]}, Action: {log[2]}, Timestamp: {log[3]}"
            )
    except Exception as e:
        print(f"Error retrieving logs: {e}")
