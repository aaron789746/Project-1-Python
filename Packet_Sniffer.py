from scapy.all import sniff, Raw, get_if_list  # type: ignore # Import necessary modules from Scapy
import re  # Import regular expressions module for pattern matching
import logging  # Import logging module to log detected threats into a file

# Configure logging to store detected threats in file "threat_log.txt"
logging.basicConfig(
    filename="threat_log.txt",
    level=logging.INFO,  # Log level (INFO to log general information)
    format="%(asctime)s - %(message)s"  # Log format with a timestamp and message
)

# Define suspicious patterns to search for in network traffic
suspi_patterns = {
    "URLs": [  # Suspicious URLs 
        b'ucoz.com', b"17ebook.co", b"sapo.pt", b"aladel.net", b"bpwhamburgorchardpark.org",
        b"clicnews.com", b"amazonaws.com", b"dfwdiesel.net", b"divineenterprises.net",
        b"fantasticfilms.ru", b"blogspot.de", b"gardensrestaurantandcatering.com",
        b"ginedis.com", b"gncr.org", b"hdvideoforums.org", b"hihanin.com", b"kingfamilyphotoalbum.com",
        b"4shared.com", b"likaraoke.com", b"mactep.org", b"magic4you.nu", b"sendspace.com",
        b"marbling.pe.kr", b"nacjalneg.info", b"pronline.ru", b"purplehoodie.com", b"qsng.cn",
        b"comcast.net", b"seksburada.net", b"sportsmansclub.net", b"stock888.cn", b"fc2.com",
        b"tathli.com", b"teamclouds.com", b"texaswhitetailfever.com", b"hotfile.com",
        b"wadefamilytree.org", b"xnescat.info", b"mail.ru", b"yt118.com", b"danger.com",
        b"badwebsite.net", b"malware-site.org", b"phishing-login.io", b"free-gift-card.ru",
        b"keylogger-download.com"
    ],
    "Keywords": [  # Suspicious keywords 
        rb'password', rb'unauthorized_access', rb'sql_injection', rb'<script>', rb'root_access',
        rb'0x[0-9a-fA-F]{8}', rb'(\d{4}[- ]){3}\d{4}'  # Credit card numbers, SQL injections, etc.
    ],
    "Commands": [  # Dangerous commands 
        rb'rm -rf', rb'sudo', rb'chmod 777', rb'pip install .*', rb'ssh .*', rb'wget .*', rb'curl .*'
    ]
}

# Function to detect unencrypted HTTP traffic
def detect_http_traffic(packet):
    """
    Warn if browsing an unencrypted HTTP website.
    """
    if Raw in packet:  # Check if packet contains payload data
        payload = bytes(packet[Raw].load)  # Extract the payload as bytes
        if b"GET " in payload or b"POST " in payload:  # Look for HTTP GET or POST request
            match = re.search(rb"Host: ([^\r\n]+)", payload)  # Extract the 'Host' header 
            if match:
                host = match.group(1).decode(errors='ignore')  # Decode host header
                if not host.startswith("https://"):  # Check if not an HTTPS connection
                    # Log and print a warning "unencrypted HTTP browsing"
                    message = f"WARNING: Browsing an unencrypted HTTP website: {host}"
                    print(message)
                    logging.warning(message)

# Function to analyze sniffed packet for suspicious patterns
def detect_suspicious_packet(packet):
    """
    Analyze each sniffed packet for suspicious patterns and log detected threats.
    """
    if Raw in packet:  # Check if packet contains payload data
        payload = bytes(packet[Raw].load)  # Extract payload as bytes

        # Loop through each category of suspicious patterns
        for category, patterns in suspi_patterns.items():
            for pattern in patterns:
                # Check if the payload matches suspicious pattern
                if re.search(pattern, payload, re.IGNORECASE):
                    # Log and print message "detected suspicious activity"
                    message = (
                        f"Suspicious activity detected! "
                        f"Category: {category} | Pattern: {repr(pattern)} | "
                        f"Packet Summary: {packet.summary()}"  # Provide summary of the packet
                    )
                    print(message)  # Display the message
                    logging.info(message)  # Log the message

    # Call the HTTP detection function
    detect_http_traffic(packet)

# Function to start sniffing packets on specified interface
def sniff_packets(interface=None):
    """
    Start sniffing packets on the specified network interface.
    """
    if interface is None:  # If no interface specified
        # Print available network interfaces
        print("Available interfaces:", get_if_list())
        # Prompt the user to input the interface they want to sniff on
        interface = input("Enter the interface to sniff on: ").strip()

    print("Starting packet analysis... Press Ctrl+C to stop.")
    # Use Scapy sniff function to capture packets
    sniff(
        iface=interface,  # Network interface to sniff on
        prn=detect_suspicious_packet,  # Callback function to process packet
        filter="tcp",  # Filter only TCP traffic
        store=False  # Do not store packets in memory
    )

# Main entry point of the script
if __name__ == '__main__':
    # Call the sniff_packets function to begin packet sniffing
    sniff_packets()
