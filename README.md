# Fintastic Phish

This script can parse single and multiple emails and analyze them to help you determine whether they are phishing emails.
_This is a work in progress._

## Usage

To use this script, run the fintastic_phish.py file with the -i flag and the path to a directory containing email files as an argument, and the -k flag and your VirusTotal API key as an argument. For example:

    python fintasticphish.py -i /path/to/directory -k api_key

## Limitations

This script makes API calls to VirusTotal. It is designed to work with the free account, which has a limit of 4 API calls per minute and 500 API calls per day. If this limit is exceeded, the script will pause for the necessary amount of time before making additional API calls. The external services used by this script may not always provide accurate or up-to-date information.
