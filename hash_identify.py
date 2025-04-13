import re
import argparse
import hashid

def identify_hash(hash_str):
    hid = hashid.HashID()
    results = hid.identifyHash(hash_str)
    
    if results:
        return [result.name for result in results]
    else:
        return ["Unknown Hash Type"]

def process_input():
    hash_input = input("Enter a hash: ").strip()
    if hash_input:
        hash_types = identify_hash(hash_input)
        print(f"\nHash: {hash_input}\nPossible Hash Types: {', '.join(hash_types)}\n")

def process_file():
    file_path = input("Enter the file path containing hashes: ").strip()
    try:
        with open(file_path, 'r') as file:
            for line in file:
                hash_input = line.strip()
                if hash_input:
                    hash_types = identify_hash(hash_input)
                    print(f"\nHash: {hash_input}\nPossible Hash Types: {', '.join(hash_types)}\n")
    except FileNotFoundError:
        print("Error: File not found!")

if __name__ == "__main__":
    print("Choose an option:\n1. Enter a hash manually\n2. Upload a file of hashes")
    choice = input("Enter 1 or 2: ").strip()
    
    if choice == "1":
        process_input()
    elif choice == "2":
        process_file()
    else:
        print("Invalid choice. Please enter 1 or 2.")
