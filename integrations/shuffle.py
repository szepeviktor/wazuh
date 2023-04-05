#!/usr/bin/env python3
# Created by Shuffle, AS. <frikky@shuffler.io>.
# Based on the Slack integration using Webhooks
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Error Codes:
#   1 - Module requests not found
#   2 - Incorrect input arguments
#   3 - Alert File does not exist
#   4 - Error getting json_alert


import json
import sys
import logging
import logging.handlers
import os
from urllib.parse import urlparse

try:
    import requests
    from requests.auth import HTTPBasicAuth
except ModuleNotFoundError as e:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(1)

# ADD THIS TO ossec.conf configuration:
#  <integration>
#      <name>shuffle</name>
#      <hook_url>http://<IP>:3001/api/v1/hooks/<HOOK_ID></hook_url>
#      <level>3</level>
#      <alert_format>json</alert_format>
#  </integration>

# Set paths
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
LOG_FILE = f'{pwd}/logs/integrations.log'

# Global vars
SKIP_RULE_IDS = ["87924", "87900", "87901", "87902", "87903", "87904", "86001", "86002", "86003", "87932",
                 "80710", "87929", "87928", "5710"]
logger = logging.getLogger("shuffle")
consoleHandler = logging.StreamHandler()
fileHandler = logging.handlers.WatchedFileHandler(LOG_FILE)
formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%a %b %d %H:%M:%S %Z %Y")
consoleHandler.setFormatter(formatter)
fileHandler.setFormatter(formatter)
logger.addHandler(consoleHandler)
logger.addHandler(fileHandler)


def main(args: list[str]):
    try:
        # Read arguments
        invalid_arguments = False
        if len(args) > 3:
            msg = '{1} {2} {3} {4}'.format(
                args[1],
                args[2],
                args[3],
                args[4].upper() if len(args) > 4 else 'INFO',
            )
        else:
            invalid_arguments = True

        if invalid_arguments:
            print_help_msg()
            sys.exit(2)

        alert_file_location = args[1]
        if not os.path.exists(alert_file_location):
            raise FileNotFoundError(f"Alert file specified {alert_file_location} does not exist")

        webhook: str = args[3]
        if not is_valid_url(webhook):
            raise Exception(f"Invalid webhook URL: {webhook}")

        if len(args) > 4:
            logger.setLevel(args[4].upper())
        else:
            logger.setLevel(logging.INFO)

        # Logging the call
        logger.debug(msg)

        # Main function
        process_args(alert_file_location, webhook)

    except Exception as e:
        logger.error(str(e))
        raise


def process_args(alert_file_location: str, webhook: str):
    logger.info("Starting")
    logger.info("Alerts file location: %s", alert_file_location)
    logger.info("Webhook: %s", webhook)

    json_alert = load_alert(alert_file_location)
    msg: str = generate_msg(json_alert)

    # Check if alert is skipped
    if isinstance(msg, str):
        if not msg:
            return

    send_msg(msg, webhook)


def load_alert(file_path: str) -> object:
    '''Load alert and parse JSON object'''
    json_alert = {}
    try:
        with open(file_path, encoding='utf-8') as f:
            json_alert = json.load(f)
    except json.decoder.JSONDecodeError as e:
        raise Exception(f"Failed getting json alert: {e}")

    logger.info("Processing alert with ID %s", json_alert["id"])
    logger.debug("Alert:\n%s", json_alert)

    return json_alert


# Skips container kills to stop self-recursion
def filter_msg(alert: object) -> bool:
    # SKIP_RULE_IDS need to be filtered because Shuffle starts Docker containers, therefore those alerts are triggered
    return not alert["rule"]["id"] in SKIP_RULE_IDS


def generate_msg(alert: object) -> str:
    logger.info("Generating message")

    if not filter_msg(alert):
        logger.info("Skipping rule %s", alert["rule"]["id"])
        return ""

    level = alert['rule']['level']

    if (level <= 4):
        severity = 1
    elif (level >= 5 and level <= 7):
        severity = 2
    else:
        severity = 3

    msg = {'severity': severity, 'pretext': "WAZUH Alert",
           'title': alert['rule']['description'] if 'description' in alert['rule'] else "N/A",
           'text': alert.get('full_log'),
           'rule_id': alert["rule"]["id"],
           'timestamp': alert["timestamp"],
           'id': alert['id'], "all_fields": alert}

    json_msg = json.dumps(msg)
    logger.debug("Message:\n%s", json_msg)

    return json_msg


def send_msg(msg: str, url: str):
    logger.info("Sending message")

    headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
    res = requests.post(url, data=msg, headers=headers, verify=False)
    if res.status_code == 200:
        logger.info("Message sent successfully")
    else:
        raise requests.HTTPError("Failed sending message", res.reason)
    
    logger.debug("Shuffle response:\nDate: %s\nStatus code: %d\nURL: %s", 
                 res.headers["date"], res.status_code, res.url)


def print_help_msg():
    help_msg = '''Exiting: Invalid arguments.
    
Usage:
    shuffle <alerts_file> [api_key] <webhook_url> [logging_level]

Arguments:
    alerts_file (required)
        Path to the JSON file containing the alerts.

    api_key (not required)
        The API key argument is not needed for the Shuffle integration. However, it's still considered because the 
        integrator executes all scripts with the same arguments.
        If you are executing the script manually, please put anything in that argument.

    webhook_url (required)
        Shuffle webhook URL where the messages will be sent to.

    logging_level (optional)
        Used to define how much information should be logged. Default is INFO.

        Levels: NOTSET, DEBUG, INFO, WARNING, ERROR, CRITICAL.
    '''
    print(help_msg)


def is_valid_url(url: str) -> bool:
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False


if __name__ == "__main__":
    main(sys.argv)
