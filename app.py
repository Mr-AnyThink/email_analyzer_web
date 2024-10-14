import os
import re
import hashlib
import email
import requests
import logging
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_cors import CORS
from mailparser import parse_from_file
from datetime import datetime, timezone
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from email.parser import BytesParser
from email import policy
from email.utils import parsedate_to_datetime


# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
CORS(app)
app.secret_key = os.getenv('SECRET_KEY', 'your_secret_key')  # Replace with your secret key

# Configure Logging
logging.basicConfig(level=logging.DEBUG)  # Set to DEBUG for detailed logs

# Configuration
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
ALLOWED_EXTENSIONS = {'eml'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# OSINT API Keys
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')

def allowed_file(filename):
    """Check if the uploaded file has an allowed extension."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def fetch_osint(entity_type, value):
    """Fetch OSINT data based on the entity type."""
    headers = {}
    api_url = ''
    params = {}

    if entity_type.lower() == 'ip':
        api_url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            'Accept': 'application/json',
            'Key': ABUSEIPDB_API_KEY
        }
        params = {
            'ipAddress': value,
            'maxAgeInDays': '90'
        }
    elif entity_type.lower() == 'domain':
        api_url = f"https://www.virustotal.com/api/v3/domains/{value}"
        headers = {
            'x-apikey': VIRUSTOTAL_API_KEY
        }
    elif entity_type.lower() == 'hash':
        api_url = f"https://www.virustotal.com/api/v3/files/{value}"
        headers = {
            'x-apikey': VIRUSTOTAL_API_KEY
        }
    else:
        return {'error': 'Invalid entity type'}

    try:
        # check if api_url is virustotal
        if 'virustotal' in api_url:
            response = requests.get(api_url, headers=headers, params=params if entity_type.lower() == 'ip' else {})
            reputaion = re.search(r'"last_analysis_stats":\s*\{"malicious":\s*(\d+)', response.text)
            if response.status_code == 200:
                return ( reputaion.group(1) + ' hits')
            else:
                logging.warning(f"OSINT data not found for {value}: {response.status_code} {response.text}")
                return 'No Hits'
        elif 'abuseipdb' in api_url:
            response = requests.get(api_url, headers=headers, params=params if entity_type.lower() == 'ip' else {})
            reputaion = re.search(r'"abuseConfidenceScore":\s*(\d+)', response.text)
            if response.status_code == 200:
                #return response.json()
                return ( 'AbuseIP Score: ' + reputaion.group(1))
            else:
                logging.warning(f"OSINT data not found for {value}: {response.status_code} {response.text}")
                return 'No Hits'
        else:
            return 'No defined Type'
    except Exception as e:
        logging.error(f"Error fetching OSINT data for {value}: {str(e)}")
        return {'error': str(e)}

def parse_authentication_results(headers):
    """Parse Authentication-Results headers to extract SPF, DKIM, and DMARC results."""
    auth_results = {
       'spf': 'None', 
       'dkim': 'None', 
       'dmarc': 'None', 
       'dmarc_from': 'None', 
       'spf_client_ip': 'None', 
       'dkim_d': 'None', 
       'dkim_s': 'None'
    }

    spf = None
    dkim = None
    dmarc = None
    dmarc_from = None
    spf_client_ip = None
    dkim_d = None
    dkim_s = None

    Authentication_Results = headers.get('Authentication-Results', None)
    if Authentication_Results:
          spf = re.search(r'spf=(\S+)', Authentication_Results)
          dkim = re.search(r'dkim=(\S+)', Authentication_Results)
          dmarc = re.search(r'dmarc=(\S+)', Authentication_Results)
          dmarc_from = re.search(r'header\.from=(\S+)', Authentication_Results)

    Received_SPF = headers.get('Received-SPF', None)
    if Received_SPF:
          spf_client_ip = re.search(r'client-ip=([\d.]+)', Received_SPF)

    dkim_signature = headers.get('DKIM-Signature', None)
    if dkim_signature:
          dkim_d = re.search(r'd=(\S+)',dkim_signature)
          dkim_s = re.search(r's=(\S+)',dkim_signature)

    auth_results['spf'] = spf.group(1) if spf else "Not Available"
    auth_results['dkim'] = dkim.group(1) if dkim else "Not Available"
    auth_results['dmarc'] = dmarc.group(1) if dmarc else "Not Available"
    auth_results['dmarc_from'] = dmarc_from.group(1) if dmarc_from else "Not Available"
    auth_results['spf_client_ip'] = spf_client_ip.group(1) if spf_client_ip else "Not Available"
    auth_results['dkim_d'] = dkim_d.group(1) if dkim_d else "Not Available"
    auth_results['dkim_s'] = dkim_s.group(1) if dkim_s else "Not Available"

    logging.info(f"auth_results : {auth_results}")
    return auth_results

def extract_hop_info(hops_headers):
    """Extract hop-by-hop information from Received headers."""
    logging.debug(f"\n+++++++++++++++++++++++++++++++++++++\nHops Analysis\n{hops_headers}\n")

    hops = []
    previous_time = None
    received_values = [item['value'] for item in hops_headers] #collect header values
    j = 0
    for received in received_values:
        j = j + 1
        hop_info = {
            'hop': j,
            'from': None,
            'from_ip': None,
            'by': None,
            'by_ip': None,
            'with': None,
            'time': None,
            'delay': None,
            'blacklist': None
        }

        # Parse "from", "by", "with", and "time" from the Received header
        logging.debug(f"{received}\n")
        from_match = re.search(r'from\s+([^\s]+)', received)
        from_ip = re.search(r'\[(\d{1,3}(?:\.\d{1,3}){3})\].*by', received)
        by_match = re.search(r'by\s+([^\s]+)', received)
        by_ip = re.search(r'by.*\[(\d{1,3}(?:\.\d{1,3}){3})\]', received)
        with_match = re.search(r'with\s+([^\s]+)', received)
        time_match = re.search(r';\s*(.*)', received)
        logging.debug(f"\ntime: {time_match.group(1)}\n")

        if from_match:
            hop_info['from'] = from_match.group(1)
        if from_ip:
            hop_info['from_ip'] = from_ip.group(1)
        if by_match:
            hop_info['by'] = by_match.group(1)
        if by_ip:
            hop_info['by_ip'] = by_ip.group(1)
        if with_match:
            hop_info['with'] = with_match.group(1)
        if time_match:
            time_str = time_match.group(1)
            try:
                parsed_time = parsedate_to_datetime(time_str)
                # If the parsed datetime is naive, assign UTC timezone
                if parsed_time.tzinfo is None:
                    parsed_time = parsed_time.replace(tzinfo=timezone.utc)
                    logging.debug(f"Assigned UTC timezone to naive datetime: {parsed_time}")
                else:
                    # Convert to UTC
                    parsed_time = parsed_time.astimezone(timezone.utc)
                    logging.debug(f"Converted datetime to UTC: {parsed_time}")

                hop_info['time'] = parsed_time
                # hop_info['time'] = datetime.strptime(time_str, '%a, %d %b %Y %H:%M:%S %z')
            except Exception as e:
                hop_info['time'] = None
                logging.debug(f"\nERROR TIME CONVERT: {e}\n")

        # Calculate delay between hops
        if hop_info['time'] and previous_time:
            try:
                delay = hop_info['time'] - previous_time
                hop_info['delay'] = str(delay)
            except Exception as e:
                hop_info['delay'] = 'Error calculating delay'
                logging.debug(f"\nERROR CALCULATING DELAY: {e}\n")
        else:
            hop_info['delay'] = '*'

        previous_time = hop_info['time']

        # Example Blacklist check (you can replace this with a real OSINT API call)
        hop_info['blacklist'] = 'Not blacklisted'  # Mocked result

        hops.append(hop_info)

    logging.debug("\n+++++++++++++++++++++++++++++++++++++\n")

    return hops

def create_hop_graph(hops):
    fig, ax = plt.subplots(figsize=(10, 4))
    
    # Calculate the number of nodes (hops) and spacing
    num_hops = len(hops)
    spacing = 3  # Distance between nodes
    
    # Position the boxes and draw arrows
    for i, hop in enumerate(hops):
        from_node = hop.get('from')
        by_node = hop.get('by')

        if from_node and by_node:
            # Draw the first server box
            box_from = FancyBboxPatch((i * spacing, 1), 2, 1, boxstyle="round,pad=0.3", edgecolor="black", facecolor="lightblue")
            ax.add_patch(box_from)
            ax.text(i * spacing + 1, 1.5, from_node, ha="center", va="center", fontsize=10)

            # Draw the second server box
            box_by = FancyBboxPatch((i * spacing + spacing, 1), 2, 1, boxstyle="round,pad=0.3", edgecolor="black", facecolor="lightblue")
            ax.add_patch(box_by)
            ax.text(i * spacing + spacing + 1, 1.5, by_node, ha="center", va="center", fontsize=10)

            # Draw the arrow connecting the boxes
            ax.annotate("", xy=(i * spacing + 2, 1.5), xytext=(i * spacing + spacing, 1.5),
                        arrowprops=dict(arrowstyle="->", lw=2))

    # Hide axes and display the flowchart
    ax.set_axis_off()
    plt.title('Email Hop Travel Flowchart')
    plt.savefig('email_hop_graph.png', bbox_inches='tight')

def extract_attachments_from_eml(eml_file_path, output_dir):
    """Extract attachments from .eml file and save them to output directory."""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    with open(eml_file_path, 'rb') as f:
        msg = email.message_from_bytes(f.read())

    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_disposition() == 'attachment':
                filename = part.get_filename()
                if filename:
                    file_path = os.path.join(output_dir, filename)
                    with open(file_path, 'wb') as att_file:
                        att_file.write(part.get_payload(decode=True))
                    attachments.append(file_path)
                    logging.info(f'Saved attachment: {file_path}')
    else:
        logging.warning("No attachments found in this email.")

    return attachments

def calculate_hash(file_path):
    """Calculate the MD5 and SHA256 hashes of the given file."""
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()

    with open(file_path, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            md5_hash.update(byte_block)
            sha256_hash.update(byte_block)

    return md5_hash.hexdigest(), sha256_hash.hexdigest()

@app.route('/')
def home():
    """Render the home page."""
    return render_template('home.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload_email():
    """Handle email upload, parsing, and analysis."""
    if request.method == 'POST':
        if 'email' not in request.files:
            flash('No file part in the request.')
            logging.warning("No file part in the request.")
            return redirect(request.url)

        file = request.files['email']
        if file.filename == '':
            flash('No file selected for uploading.')
            logging.warning("No file selected for uploading.")
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            logging.info(f"Saved uploaded file to {filepath}")
            analysis = process_email(filepath) # pass the email file to analysis
            return render_template('results.html', analysis=analysis)
        else:
            flash('Allowed file types are .eml')
            logging.warning("Attempted to upload a file with disallowed extension.")
            return redirect(request.url)
    return render_template('upload.html')


def process_email(filepath):
         # Extract attachments
         attachments = extract_attachments_from_eml(filepath, app.config['UPLOAD_FOLDER'])

         # Calculate hash for each attachment
         attachment_hashes = []
         for att in attachments:
             logging.debug(f"Processing attachment: {att}")
             md5, sha256 = calculate_hash(att)
             logging.debug(f"MD5: {md5}, SHA256: {sha256}")
             osint_data = fetch_osint('hash', sha256)
             attachment_hashes.append({
                 'filename': os.path.basename(att),
                 'hash_md5': md5,       # Updated key name
                 'hash_sha256': sha256,  # Updated key name
                 'vt': osint_data
             })
             logging.info(f"virus total hash : {osint_data}")

         # Parse the email
         parsed = parse_from_file(filepath)

         # Read the email
         with open(filepath, 'rb') as f:
             raw_email = f.read()
         email_message = BytesParser(policy=policy.default).parsebytes(raw_email)


         # OSINT IPs From Received
         entities = []
         if 'Received' in email_message:
             hops = email_message.get_all('Received')
             ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
             for hop in hops:
                 ips = ip_pattern.findall(hop)
                 logging.debug(f"Found IPs in header '{hop}': {ips}")
                 for ip in ips:
                     entities.append({'type': 'IP', 'value': ip})

         # Remove duplicate entities
         unique_entities = { (e['type'], e['value']) for e in entities }
         entities = [{'type': t, 'value': v} for t, v in unique_entities]

         # Fetch OSINT data
         osint_results = []
         for entity in entities:
             osint_data = fetch_osint(entity['type'], entity['value'])
             osint_results.append({
                 'entity_type': entity['type'],
                 'value': entity['value'],
                 'osint': osint_data
             })
             logging.debug(f"OSINT data for {entity['type']} {entity['value']}: {osint_data}")

         # Remove duplicate entities
         # unique_entities = { (e['type'], e['value']) for e in entities }
         # entities = [{'type': t, 'value': v} for t, v in unique_entities]
         # logging.debug(f"Unique OSINT entities: {entities}")


         # Get received in reverse order
         received_headers = email_message.get_all('Received')
         received_reverse = []
         if received_headers:
            # Print the headers in reverse order
            print("Received headers in reverse order:")
            for i, received in enumerate(reversed(received_headers), 1):
              print(f"{i}. {received}")
              received_reverse.append({'type': 'string', 'value': received})
         else:
            print("No 'Received' headers found.")


         # Extract Specific Headers for Table
         specific_headers = {
              "From": email_message['From'],
              "To": email_message['To'],
              "Subject": email_message['Subject'],
              "Date": email_message['Date'],
              "Message_ID": email_message['Message-ID'],
              "Return-Path": email_message['Return-Path'],
              "Reply_To": email_message['Reply-To'],
              "Received": received_reverse,
         }

         # Hops Analysis
         hop_analysis = extract_hop_info(received_reverse)

         # Header Analysis
         headers = parsed.headers
         logging.debug(f"Extracted headers: {headers}")

         # Extract URLs from email
         urls = []
         if parsed.body:
             urls += re.findall(r'(https?://[^\s]+)\"', parsed.body)  # Removed unnecessary quote
             logging.debug(f"Extracted URLs from body: {urls}")
         else:
             logging.debug("No body found in the email for URL extraction.")

         unique_urls = list(set(urls))
         logging.debug(f"Unique URLs after deduplication: {unique_urls}")


         # Parse Authentication Results
         authentication = parse_authentication_results(email_message)

         logging.debug(f"\n\n++++++++++++++++++++++++++++++++++\n")
         logging.debug(f"Authentication results: {authentication}\n\n")
         logging.debug(f"Header Parsed: {specific_headers}\n\n")

         # Prepare data for results
         analysis = {
             'specific_headers': specific_headers,  # Add specific headers for table
             'headers': headers,
             'email': email_message,
             'urls': list(set(urls)),  # Remove duplicates from URLs
             'attachments': attachment_hashes,  # Include hashes for attachments
             'osint': osint_results,
             'authentication': authentication,
             'hop_analysis': hop_analysis
         }

         logging.info("Completed email analysis.")
         return analysis

         #return render_template('results.html', analysis=analysis)

@app.route('/analyze_header', methods=['GET', 'POST'])
def analyze_header():
    """Handle header analysis requests."""
    if request.method == 'POST':
        header_text = request.form['header']
        logging.info(f"Header to analyze: {header_text}")

        # Create a temporary .eml file with the provided header content
        filename = "analyzed_header.eml"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        with open(filepath, 'w') as f:
            f.write(header_text)

        logging.info(f"Created .eml file at {filepath} with header content")
        if allowed_file(filepath):
            analysis = process_email(filepath) # pass the email file to analysis
            return render_template('results.html', analysis=analysis)
        else:
            flash('Allowed file types are .eml')
            return redirect(request.url)
    return render_template('analyze_header.html')

@app.route('/download/<filename>')
def download_file(filename):
    """Serve the attachment for download."""
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(filepath):
        flash('File does not exist.')
        logging.error(f"Download attempted for non-existent file: {filename}")
        return redirect(url_for('home'))

    logging.info(f"Serving file for download: {filename}")
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
