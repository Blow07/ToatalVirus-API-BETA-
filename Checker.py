import requests
import logging
import argparse
import sys
import os

# Initialize the logging
logging.basicConfig(filename="app.log",level=logging.DEBUG,filemode="w")
url = "https://www.virustotal.com/api/v3/files" # The API url

# Getting the file name and arguments with argparse
parser = argparse.ArgumentParser(description="Use this programm to check safety of files:\n Syntax: python3 Checker.py \"target_name\" ")
parser.add_argument("target_name", type=str, help="The file name or the folder name if you use the -r option")
parser.add_argument("-r", default=False, action="store_true", help="use this option to check all the files in a folder")
args = parser.parse_args()
target_name = args.target_name


def check_file(path,url):
    try:
        headers = {
        "accept": "application/json",
        "x-apikey": "4088f4bd9e11249f9388367587d499feecf7a274aa05944215bfe8967bb4818d"
    }
        files = { "file": (f"{path}", open(f"{path}", "rb"), "application/octet-stream")}
    except Exception as e:
        print("Invalid name or invalid file, see the log file")
        logging.error(e)
        sys.exit()
    else:
        response = requests.post(url, files=files, headers=headers)
        response_text = response.text
        response_json = response.json()
        logging.info(response_text)
        print("File uploaded successfully, see the log file")

    id_file = response_json.get("data").get("id")
    url = f"https://www.virustotal.com/api/v3/analyses/{id_file}"
    headers = {
        "accept": "application/json",
        "x-apikey": "4088f4bd9e11249f9388367587d499feecf7a274aa05944215bfe8967bb4818d"
    }
    try:
        response = requests.get(url, headers=headers)
    except Exception as e:
        logging.error(e)

    path = path.split("/")[1]
    with open(f"{path}.json", "w") as file:
        response_text = response.text
        file.write(response_text)
        logging.info("File saved !")
        print("File saved !")

if args.r:
    if os.path.exists(target_name):
        try:
            all_files = os.listdir(target_name)
        except Exception as e:
            print("Error when trying to open folder, see the log file")
            logging.error(e)
            sys.exit()

        for file in all_files:
            path = f"{target_name}/{file}"
            check_file(path, url)
    else:
        print("Invalid folder name ! Please make sure that the folder is in the same directory")
        sys.exit()
else:
    check_file(target_name, url)



