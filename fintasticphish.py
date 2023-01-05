import argparse
import os
import re
import socket
import time
import email
import pytz
import requests
import datetime


from prettytable import PrettyTable


REQUESTS_PER_MINUTE = 4
SECONDS_PER_MINUTE = 60
REQUESTS_PER_DAY = 500
SECONDS_PER_DAY = 86400

last_request_time = 0
requests_today = 0

def decode_email_subject(email_subject):
    if email_subject is None:
        return None
    decoded_subject = email.header.decode_header(email_subject)
    subject_parts = []
    for s in decoded_subject:
        if s[1] is None:
            # Assume ASCII if character set is not specified
            subject_parts.append(str(s[0]))
        else:
            try:
                # Try to decode using specified character set
                subject_parts.append(s[0].decode(s[1]))
            except UnicodeDecodeError:
                # If decoding fails, try to decode using Quoted-Printable encoding
                subject_parts.append(s[0].decode('quoted-printable'))
    return ''.join(subject_parts)


def reverse_lookup_hostname(ip_address):
    if ip_address is None:
        return None
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname
    except socket.herror:
        print(f"Error: Reverse DNS lookup failed for IP address {ip_address}")
        return None


def parse_email(email_file):
    with open(email_file, 'r') as f:
        email_message = email.message_from_file(f)
        email_subject = email_message['Subject']
        if email_subject is not None:
            email_subject = decode_email_subject(email_subject)
        email_sender = email_message['From']
        email_date = email_message['Date']
        email_receiver = email_message['To']
        email_reply_to = email_message['Reply-To']
        email_bcc = email_message['Bcc']
 
        return (email_subject, email_sender, email_date, email_receiver, email_reply_to, email_bcc)


def extract_urls_from_email(email_file):
    with open(email_file, 'r') as f:
        email_message = email.message_from_file(f)
        # Compile a regular expression to match URLs
        url_regex = re.compile(r'((?:https?://|www\d{0,3}[.])[^\s]+)')
        # Extract all email_links from the email
        email_links = find_urls_in_eml(email_file)
        pretty_email_links = []
        for link in email_links:
            # Use the regular expression to search for URLs in the link
            match = url_regex.search(link)
            if match:
                pretty_email_links.append(match.group())
        # Remove duplicates
        formatted_email_urls = list(set(pretty_email_links))
        return formatted_email_urls


def get_sender_ip_and_hostname(email_file):
    with open(email_file, 'r') as f:
        email_message = email.message_from_file(f)
        _, sender_ip = find_sender_ip(email_message.as_string())
        sender_hostname = reverse_lookup_hostname(sender_ip)
        return sender_ip, sender_hostname


def process_email(email_file):
    email_subject, email_sender, email_date, email_receiver, email_reply_to, email_bcc = parse_email(email_file)
    # Convert the date to UTC
    email_utc_date = convert_date_to_utc(email_date)
    email_sender_ip, email_sender_hostname = get_sender_ip_and_hostname(email_file)
    email_attachments = []
    email_urls = extract_urls_from_email(email_file)
    return (email_utc_date, email_subject, email_sender, email_receiver, email_reply_to, email_bcc, email_sender_ip, email_sender_hostname, email_attachments, email_urls)


def scan_url(scanned_url, api_key):
    global last_request_time
    global requests_today

    data = {'apikey': api_key, 'resource': scanned_url}

    if last_request_time != 0 and time.time() - last_request_time < SECONDS_PER_MINUTE / REQUESTS_PER_MINUTE:
        # Sleep for the remaining time in the current minute
        time.sleep(SECONDS_PER_MINUTE / REQUESTS_PER_MINUTE - (time.time() - last_request_time))

    if requests_today >= REQUESTS_PER_DAY:
        # Sleep until the next day
        time.sleep(SECONDS_PER_DAY - (time.time() % SECONDS_PER_DAY))
        requests_today = 0

    # Make the request
    response = requests.post('https://www.virustotal.com/vtapi/v2/url/report', data=data)

    # Update the last request time and requests today count
    last_request_time = time.time()
    requests_today += 1

    if response.status_code == 200:
        data = response.json()
        # Return the response data
        return data
    else:
        # If the request failed, return the status code
        return response.status_code



def parse_result(result):
    if result is None:
        return "No VirusTotal results."
    if result["verbose_msg"] == "Resource does not exist in the dataset":
        return "No VirusTotal results."
    scans = result["scans"]
    output = []
    for scan, details in scans.items():
        if details["detected"]:
            output.append(f"{scan}: {details['result']}")

            
    if len(output) > 0:
        return "\n".join(output) + "\n" + result["permalink"]
    return "No malicious reports found." + "\n" + result["permalink"]


def print_table(results, api_key, page_size):
    num_pages = len(results) // page_size + 1
    for page_num in range(num_pages):
        page = results[page_num * page_size : (page_num + 1) * page_size]
        header_table = PrettyTable()
        header_table.field_names = ['ID', 'Date', 'Subject', 'Sender', 'Receiver', 'Reply-To', 'Bcc']
        sender_table = PrettyTable()
        sender_table.field_names = ['ID', 'IP Address', 'rDNS', 'Attachments']
        virustotal_table = PrettyTable()
        virustotal_table.field_names = ['ID', 'URL', 'VirusTotal Report']
        for i, result in enumerate(page):
            id_ = page_num * page_size + i + 1  # Generate an ID for each row
            header_table.add_row([id_] + list(result[:6]))
            sender_table.add_row([id_] + list(result[6:9]))
            # Loop through the URLs in result[9] and add a row for each URL
            for url in result[9]:
                report = scan_url(url, api_key)
                if isinstance(report, int):  # If report is an integer (status code)
                    if report == 200:
                        stats = parse_result(report)
                        virustotal_table.add_row([id_, url, stats])
                    elif report == 204:
                        virustotal_table.add_row([id_, url, "Request rate limit exceeded"])
                    elif report == 400:
                        virustotal_table.add_row([id_, url, "Bad request"])
                    elif report == 403:
                        virustotal_table.add_row([id_, url, "Forbidden"])
                elif report is not None:  # Only run parse_result if report is not None
                    stats = parse_result(report)
                    virustotal_table.add_row([id_, url, stats])
                else:  # If report is None (error occurred)
                    virustotal_table.add_row([id_, url, "Error occurred"])

        print(header_table)
        print(sender_table)
        print(virustotal_table)


def find_sender_ip(text):
    ip4_pattern = r'(?P<context>.*?)(?P<ip_address>\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b)'
    ip6_pattern = r'(?P<context>.*?)(?P<ip_address>\b[0-9a-fA-F:]+\b)'
    lines = text.split('\n')
    for line in lines:
        if 'Received-SPF' in line:
            matches = re.finditer(ip4_pattern, line)
            for match in matches:
                context = match.group('context')
                ip_address = match.group('ip_address')
                return (context, ip_address)
            matches = re.finditer(ip6_pattern, line)
            for match in matches:
                context = match.group('context')
                ip_address = match.group('ip_address')
                return (context, ip_address)
    return (None, None)


def convert_date_to_utc(date_string):
    # Parse the date string into a datetime object
    date_tuple = email.utils.parsedate_tz(date_string)
    if date_tuple:
        # If the timezone is not specified, use the local timezone
        if date_tuple[-1] is None:
            local_tz = pytz.timezone('local')
            date = local_tz.localize(datetime.datetime.fromtimestamp(email.utils.mktime_tz(date_tuple)))
        else:
            date = datetime.datetime.fromtimestamp(email.utils.mktime_tz(date_tuple))
        # Convert the datetime object to UTC
        utc_tz = pytz.timezone('UTC')
        utc_date = date.astimezone(utc_tz)
        return utc_date
    return None


def find_urls_in_eml(email_file):
    # Regular expression to match URLs
    URL_REGEX = r'(?:(?:https?|ftp):\/\/)?[\w/\-?=%.]+\.[\w/\-?=%.]+'

    # Initialize the list of URLs
    email_urls = []
    # Open the EML file
    with open(email_file, 'r') as f:
        # Parse the EML file into a message object
        raw_email = email.message_from_file(f)

        # Iterate through all parts of the email
        for part in raw_email.walk():
            # Check if the part is a link
            content_type = part.get_content_type()
            if 'text' in content_type and 'html' in content_type:
                # Extract all email_links from the HTML part
                email_urls.extend(re.findall(URL_REGEX, part.get_payload()))

    # Return the list of URLs
    return email_urls

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input', help='The directory or file to process', type=str)
    parser.add_argument('-k', '--api-key', default=os.environ.get('API_KEY'), help='API key for VirusTotal')
    return parser.parse_args()

def get_email_files(input_path):
    email_files = []
    for root, dirs, files in os.walk(input_path):
        for file in files:
            if file.endswith('.eml'):
                email_files.append(os.path.join(root, file))
    return email_files

def process_input(input_path):
    results = []
    # Check if the input is a directory or a file
    if os.path.isdir(input_path):
        # Process the directory
        print(f'Processing directory: {input_path}')
        
        # Collect all the .eml files in the directory
        email_files = get_email_files(input_path)
                    
        # Process the email files
        for email_file in email_files:
            # Store the result of the process_email function in the results list
            results.append(process_email(email_file))
            
    elif os.path.isfile(input_path):
        # Process the file
        print(f'Processing file: {input_path}')
        # Store the result of the process_email function in the results list
        results.append(process_email(input_path))
    else:
        # Print an error message if the input is neither a directory nor a file
        print(f'Error: {input_path} is not a directory or a file')
    return results

def main():
    args = parse_args()
    input_path = args.input
    api_key = args.api_key

    results = process_input(input_path)
    print_table(results, api_key, page_size=10)




if __name__ == '__main__':
    main()

