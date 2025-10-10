import os # to interact with os
import hashlib # to get hashing algorithms
import json # functions to work with json
import time # provides real time
import logging # to record and log events and errors    
import schedule # provides a schedule to run tasks at specified intervel
import requests # http requests
from dotenv import load_dotenv # to load from .env

# Load from .env file
load_dotenv()
JIRA_EMAIL = os.getenv("JIRA_EMAIL")
JIRA_API_KEY = os.getenv("JIRA_API_KEY")

# Configuration
FOLDER_TO_MONITOR = r"/home/Shadin/Desktop/weeks/"  # the folder that needed to be checked
HASH_STORAGE_FILE = "./file_hashes.json" # the file which hashed values are stored (json)
JIRA_URL = "https://shdnkval.atlassian.net" # url for jira imstance
JIRA_PROJECT_KEY = "KAN" # project key of jira
JIRA_AUTH = (JIRA_EMAIL, JIRA_API_KEY) 
JIRA_ISSUE_TYPE = "Bug"  # issue type of jira project (Bug)

# Set up logging
logging.basicConfig(
    filename="file_integrity.log", # to log filename
    level=logging.INFO, # logging level (error,warning,info)
    format="%(asctime)s - %(levelname)s - %(message)s" # message format of loggging 
)

def calculate_file_hash(filepath, hash_algo="sha256"):
    """Calculate the hash value of a file."""
    hash_func = hashlib.new(hash_algo) # Create a new hash object using the specified algorithm
    try:
        with open(filepath, "rb") as f:  # Open the file in binary mode
            for chunk in iter(lambda: f.read(4096), b""):  # Read the file in chunks of 4096 byt
                hash_func.update(chunk) #updating the hash objects with the current chunks
        return hash_func.hexdigest() # returning the hexadecimal digest of the hash
    except Exception as e:
        logging.error(f"Error calculating hash for {filepath}: {e}") # logging any errors
        return None

def load_stored_hashes():
    """Load previously stored file hashes from JSON."""
    if os.path.exists(HASH_STORAGE_FILE):  # it Check if the hash storage file exists
        try:
            with open(HASH_STORAGE_FILE, "r") as f: # Open the file in read mode
                return json.load(f) # Load and return the JSON data as a dictionary
        except json.JSONDecodeError:
            logging.error("Error decoding JSON from hash storage file. Starting with an empty hash store.")
    return {}

def save_hashes(hashes):
    """Save current file hashes to JSON."""
    try:
        with open(HASH_STORAGE_FILE, "w") as f: # Open the file in write mode
            json.dump(hashes, f, indent=4)  # Write the dictionary to the file with indentation
    except Exception as e:
        logging.error(f"Error saving hashes to file: {e}")  # Log any errors

def scan_folder():
    """Scan the folder and calculate file hashes."""
    file_hashes = {} # Initialize an empty dictionary to store file hashes
    try:
        for root, _, files in os.walk(FOLDER_TO_MONITOR): # it goes through evry folder and its sub 
            for file in files: # Iterate over each file in the folder
                filepath = os.path.join(root, file)  # Get the full path of the file
                file_hash = calculate_file_hash(filepath) # Calculate the hash of the file
                if file_hash:
                    file_hashes[filepath] = file_hash # Store the file path and its hash in the dictionary
    except Exception as e:
        logging.error(f"Error scanning folder: {e}") # Log any errors
    return file_hashes # Return the dictionary of file hashes

def create_jira_ticket(file_path, change_type):
    """Create a Jira ticket for a detected change."""
    issue_data = {
        "fields": {
            "project": {"key": JIRA_PROJECT_KEY}, # Specify the Jira project key
            "summary": f"File Integrity Issue: {change_type} - {os.path.basename(file_path)}", # Ticket summary
            "description": f"A {change_type} was detected for the file: {file_path}. Please investigate.", # Ticket description
            "issuetype": {"name": JIRA_ISSUE_TYPE} # Specify the issue type
        }
    }
    try:
        response = requests.post(
            f"{JIRA_URL}/rest/api/2/issue", # Jira API endpoint for creating issues
            json=issue_data, # Send the issue data as JSON
            auth=JIRA_AUTH, # Authenticate using Jira credentials
            headers={"Content-Type": "application/json"} # Set the content type to JSON
        )
        if response.status_code == 201: # Check if the request was successful
            logging.info(f"Jira ticket created for {change_type} - {file_path}") # log success
        else:
            logging.error(f"Failed to create Jira ticket for {file_path}: {response.status_code} - {response.text}") # log failure
    except Exception as e:
        logging.error(f"Error creating Jira ticket: {e}")  # log any error

def monitor_file_integrity():
    """Monitor file integrity and create Jira tickets for changes."""
    logging.info("Starting file integrity check...") # Logging at the start of the integrity check
    
    stored_hashes = load_stored_hashes() # to Load previously stored file hashes
    current_hashes = scan_folder() # scan the folder to get the current hashes

    # Check for modifications and new files
    for filepath, current_hash in current_hashes.items():
        stored_hash = stored_hashes.get(filepath) # Get the stored hash for the file

        if stored_hash and stored_hash != current_hash: # Check if the file was modified
            logging.warning(f"Integrity issue detected: {filepath}") # Log the modification
            create_jira_ticket(filepath, "Modification") # Create a Jira ticket for the modification

        elif not stored_hash: # Check if the file is new
            logging.warning(f"New file detected: {filepath}") # Log the new file
            create_jira_ticket(filepath, "New File") # Create a Jira ticket for the new file

    # Check for removed files
    for filepath in stored_hashes: 
        if filepath not in current_hashes: # Check if the file was removed
            logging.warning(f"File removed: {filepath}") # Log the file removal
            create_jira_ticket(filepath, "File Removal") # Create a Jira ticket for the file removal

    save_hashes(current_hashes)  # Save the current file hashes to the JSON file
    logging.info("File integrity check completed.") # Log the completion of the integrity check

# Schedule the task to run every 1 minute
schedule.every(1).minutes.do(monitor_file_integrity) 

if __name__ == "__main__":
    logging.info("File integrity monitor started...") # Log the start of the script
    monitor_file_integrity() # Run the integrity check once initially
    while True:
        schedule.run_pending() # Run any pending scheduled tasks
        time.sleep(60)  # Sleep for 60 seconds (1 minute)