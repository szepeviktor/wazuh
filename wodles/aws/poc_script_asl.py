#!/usr/bin/env python3
import argparse
import boto3
import json
import logging
import os
import socket
import sys
import time

logger_name = ':asl_poc:'
logging_date_format = '%Y/%m/%d %I:%M:%S'
log_levels = {0: logging.WARNING,
              1: logging.INFO,
              2: logging.DEBUG}

# logging.basicConfig(filename="aws_asl.log", level=logging.DEBUG)
logger = logging.getLogger(logger_name)
logging_format = logging.Formatter(fmt='%(asctime)s %(name)s - %(levelname)s - %(message)s', datefmt=logging_date_format)

stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setFormatter(logging_format)

logger.addHandler(stdout_handler)
logger.setLevel(log_levels.get(2, logging.DEBUG))

try:
    import awswrangler as wr
except ImportError:
    logger.error('awswrangler module is required.')
    sys.exit(2)

def check_wazuh_queue_status():
    wazuh_path = find_wazuh_path()
    wazuh_queue = '{0}/queue/sockets/queue'.format(wazuh_path)

    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        s.connect(wazuh_queue)

        s.close()
    except socket.error as e:
        if e.errno == 111:
            logger.error("Wazuh must be running.")
            sys.exit(11)
    except Exception as e:
        logger.error("Error checking wazuh status: {}".format(e))
        sys.exit(13)


def send_msg(msg, msg_header, wazuh_queue, dump_json=True):
    """
        Sends an AWS event to the Wazuh Queue

        :param msg: JSON message to be sent.
        :param dump_json: If json.dumps should be applied to the msg
        """
    try:
        json_msg = json.dumps(msg, default=str)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        s.connect(wazuh_queue)
        s.send("{header}{msg}".format(header=msg_header,
                                      msg=json_msg if dump_json else msg).encode())
        s.close()
    except socket.error as e:
        if e.errno == 111:
            logger.error("Wazuh must be running.")
            sys.exit(11)
        elif e.errno == 90:
            logger.error("Message too long to send to Wazuh.  Skipping message...")
        else:
            logger.error("Error sending message to wazuh: {}".format(e))
            sys.exit(13)
    except Exception as e:
        logger.error("Error sending message to wazuh: {}".format(e))
        sys.exit(13)


def find_wazuh_path() -> str:
    """
    Get the Wazuh installation path.

    Returns
    -------
    str
        Path where Wazuh is installed or empty string if there is no framework in the environment.
    """
    abs_path = os.path.abspath(os.path.dirname(__file__))
    allparts = []
    while 1:
        parts = os.path.split(abs_path)
        if parts[0] == abs_path:  # sentinel for absolute paths
            allparts.insert(0, parts[0])
            break
        elif parts[1] == abs_path:  # sentinel for relative paths
            allparts.insert(0, parts[1])
            break
        else:
            abs_path = parts[0]
            allparts.insert(0, parts[1])

    wazuh_path = ''
    try:
        for i in range(0, allparts.index('wodles')):
            wazuh_path = os.path.join(wazuh_path, allparts[i])
    except ValueError:
        pass

    return wazuh_path


def get_sqs_client(access_key=None, secret_key=None, region=None, profile_name=None):
    conn_args = {}
    conn_args['region_name'] = region

    if access_key is not None and secret_key is not None:
        conn_args['aws_access_key_id'] = access_key
        conn_args['aws_secret_access_key'] = secret_key
    elif profile_name is not None:
        conn_args['profile_name'] = profile_name

    boto_session = boto3.Session(**conn_args)

    try:
        sqs_client = boto_session.client(service_name='sqs')
    except Exception as e:
        logger.error("Error getting SQS client. Check your credentials file: {}".format(e))
        sys.exit(3)

    return sqs_client


def fetch_message_from_queue(sqs_client, sqs_queue: str):  # Can be more than one
    try:
        logger.debug(f'Retrieving messages from: {sqs_queue}')
        msg = sqs_client.receive_message(QueueUrl=sqs_queue, AttributeNames=['All'], MaxNumberOfMessages=10)
        return msg
    except Exception as e:
        logger.error("Error receiving message from SQS: {}".format(e))
        sys.exit(4)


def get_messages(sqs_client, sqs_queue):
    messages = []
    sqs_message = fetch_message_from_queue(sqs_client, sqs_queue)
    sqs_messages = sqs_message.get('Messages', [])
    for mesg in sqs_messages:
        body = mesg['Body']
        msg_handle = mesg["ReceiptHandle"]
        message = json.loads(body)
        parquet_path = message["detail"]["object"]["key"]
        bucket_path = message["detail"]["bucket"]["name"]
        path = "s3://" + bucket_path + "/" + parquet_path
        messages.append({"parquet_location": path, "handle": msg_handle})
    return messages





def process_events_in_s3(messages, sqs_client, sqs_queue):
    if not messages:
        logger.debug('No messages found in SQS queue, will retry in 20 seconds')
        time.sleep(20)
    for message in messages:
        logger.debug(f'Retrieving parquet from: {message["parquet_location"]}')
        asl_events_df = wr.s3.read_parquet(path=message["parquet_location"], path_suffix=".gz.parquet")
        asl_events = [row.to_json() for row in asl_events_df.iloc]
        logger.debug(f'Number of OCSF events extracted from parquet: {len(asl_events)}')
        wazuh_path = find_wazuh_path()
        wazuh_queue = '{0}/queue/sockets/queue'.format(wazuh_path)

        for event in asl_events:
            send_msg(msg=event, msg_header="1:Wazuh-AWS:", wazuh_queue=wazuh_queue, dump_json=False)
        
        sqs_client.delete_message(QueueUrl=sqs_queue,ReceiptHandle=message["handle"])

        logger.info(f"{len(asl_events)} events successfully sent to Analysisd and erased from SQS queue\n")



def get_script_arguments():
    parser = argparse.ArgumentParser(usage="usage: %(prog)s [options]",
                                     description="ASL PoC script",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-q', '--queue', dest='sqs_queue',
                        help='Specify the SQS queue URL containing the notifications',
                        action='store', required=True)
    parser.add_argument('-p', '--purge', dest='sqs_purge', help='Specify if the SQS queue is to be purged at start',
                        action='store_true')
    parser.add_argument('-n', '--notifications', dest='sqs_notifs',
                        help='Specify the amount of SQS notifications to get',
                        action='store')

    parsed_args = parser.parse_args()

    return parsed_args


def purge_sqs(sqs_client, sqs_queue, sqs_purge):
    if sqs_purge:
        logger.info('Purging SQS queue, please wait a minute..:')
        sqs_client.purge_queue(QueueUrl=sqs_queue)
        time.sleep(60) # The message deletion process takes up to 60 seconds.
        logger.debug('SQS queue purged succesfully')


def main():
    options = get_script_arguments()

    try:
        check_wazuh_queue_status()

        client = get_sqs_client()
        purge_sqs(client, options.sqs_queue, options.sqs_purge)
        if options.sqs_notifs:
            cond = int(options.sqs_notifs)
            for i in range(cond):
                messages = get_messages(client, options.sqs_queue)
                process_events_in_s3(messages, client, options.sqs_queue)
        else:
            while True:
                messages = get_messages(client, options.sqs_queue)
                process_events_in_s3(messages, client, options.sqs_queue)

    except Exception as err:
        logger.error("{}".format(err))
        sys.exit(1)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        logger.error("Unknown error: {}".format(e))
        sys.exit(1)
