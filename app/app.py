import streamlit as st
import os
import json
from web3 import Web3
import json
import logging
import random
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

def add_email_matcher(nlp):
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    matcher = spacy.matcher.Matcher(nlp.vocab)
    matcher.add("EMAIL", [[{"TEXT": {"REGEX": email_pattern}}]])
    return matcher
@st.cache_resource
def load_nlp_model():
    nlp = spacy.load("en_core_web_sm")
    email_matcher = add_email_matcher(nlp)
    return nlp, email_matcher

nlp, email_matcher = load_nlp_model()

def redact_entities(text: str, entity_types: List[str], custom_words: Optional[List[str]] = None, 
                    redaction_level: str = "Low") -> Tuple[str, List[Tuple[int, int, str, str]]]:
    doc = nlp(text)
    redactions = []

    def partially_redact(word: str, level: str) -> str:
        if level == "High":
            return "[Redacted]"
        elif level == "Medium":
            return word[:len(word)//2] + "x" * (len(word) - len(word)//2)
        else:
            return f"{word[:len(word)//2]}-xxxx"

    if custom_words:
        for word in custom_words:
            for match in re.finditer(re.escape(word), text, re.IGNORECASE):
                redactions.append((match.start(), match.end(), "[REDACTED CUSTOM]", "CUSTOM"))

    if "EMAIL" in entity_types:
        email_matches = email_matcher(doc)
        for _, start, end in email_matches:
            redacted = partially_redact(text[start:end], redaction_level)
            redactions.append((start, end, redacted, "EMAIL"))

    for ent in doc.ents:
        if ent.label_ in entity_types:
            redacted = partially_redact(ent.text, redaction_level)
            redactions.append((ent.start_char, ent.end_char, redacted, ent.label_))

    redactions.sort(key=lambda x: x[1], reverse=True)

    for start, end, replacement, label in redactions:
        text = text[:start] + replacement + text[end:]

    return text, redactions
def generate_fake_data(entity_type: str) -> str:
    if entity_type == "PERSON":
        return "John Doe"
    elif entity_type == "ORG":
        return "ACME Corporation"
    elif entity_type == "GPE":
        return "Anytown"
    elif entity_type == "DATE":
        return "01/01/2000"
    elif entity_type == "EMAIL":
        return f"user{random.randint(1000, 9999)}@example.com"
    else:
        return "".join(random.choices(string.ascii_letters + string.digits, k=10))
def mask_data(text: str, entity_types: List[str], custom_words: Optional[List[str]] = None) -> str:
    doc = nlp(text)
    masked_text = text

    if custom_words:
        for word in custom_words:
            masked_text = re.sub(re.escape(word), generate_fake_data("CUSTOM"), masked_text, flags=re.IGNORECASE)

    if "EMAIL" in entity_types:
        email_matches = email_matcher(doc)
        for _, start, end in reversed(email_matches):
            fake_email = generate_fake_data("EMAIL")
            masked_text = masked_text[:start] + fake_email + masked_text[end:]

    for ent in reversed(doc.ents):
        if ent.label_ in entity_types:
            fake_data = generate_fake_data(ent.label_)
            masked_text = masked_text[:ent.start_char] + fake_data + masked_text[ent.end_char:]

    return masked_text
def anonymize_data(text: str, entity_types: List[str], custom_words: Optional[List[str]] = None) -> str:
    doc = nlp(text)
    anonymized_text = text

    def generate_anonymous_id() -> str:
        return "".join(random.choices(string.ascii_uppercase + string.digits, k=8))

    if custom_words:
        for word in custom_words:
            anonymized_text = re.sub(re.escape(word), generate_anonymous_id(), anonymized_text, flags=re.IGNORECASE)

    if "EMAIL" in entity_types:
        email_matches = email_matcher(doc)
        for _, start, end in reversed(email_matches):
            anonymous_id = generate_anonymous_id()
            anonymized_text = anonymized_text[:start] + anonymous_id + "@anon.com" + anonymized_text[end:]

    for ent in reversed(doc.ents):
        if ent.label_ in entity_types:
            anonymous_id = generate_anonymous_id()
            anonymized_text = anonymized_text[:ent.start_char] + anonymous_id + anonymized_text[ent.end_char:]

    return anonymized_text
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
