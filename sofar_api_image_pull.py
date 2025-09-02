# # filename: sofar_api_image_pull.py
# # description: parse the data from API and save images + CSV file with summary of lat, lon, filename, and message
# #
# # Copyright 2025 Nick Raymond
# #
# # Licensed under the Apache License, Version 2.0 (the "License");
# # you may not use this file except in compliance with the License.
# # You may obtain a copy of the License at
# #
# #     http://www.apache.org/licenses/LICENSE-2.0
# #
# # Unless required by applicable law or agreed to in writing, software
# # distributed under the License is distributed on an "AS IS" BASIS,
# # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# # See the License for the specific language governing permissions and
# # limitations under the License.
# import argparse
# import os
# import re
# import base64
# import requests
# import csv
# from collections import defaultdict
#
#
# # Directory where parsed images and text files will be saved
# img_directory = 'parsed_images'
# csv_filename = 'spotter_data.csv'
# image_log_filename = 'spotter_image_log.csv'  # New CSV file for image logs
# TXT_TAG = "<T>"
#
# # Ensure the directories exist
# if not os.path.exists(img_directory):
#     os.makedirs(img_directory)
#
# csv_path = os.path.join(img_directory, csv_filename)
# image_log_path = os.path.join(img_directory, image_log_filename)
#
# # Ensure the CSV files exist and write headers if they don't
# if not os.path.exists(csv_path):
#     with open(csv_path, mode='w', newline='') as file:
#         writer = csv.writer(file)
#         writer.writerow(["Timestamp", "Latitude", "Longitude", "Node ID", "Decoded Value"])  # CSV header for text data
#
# if not os.path.exists(image_log_path):
#     with open(image_log_path, mode='w', newline='') as file:
#         writer = csv.writer(file)
#         writer.writerow(["Timestamp", "Latitude", "Longitude", "Node ID", "Filename", "File Size (bytes)"])  # CSV header for image logs
#
# def json_to_csv(csv_path, json_data):
#     # Check if 'data' is in json_data and if it's a list
#     if 'data' in json_data and isinstance(json_data['data'], list):
#
#         # Open the file for writing
#         with open(csv_path, mode='w', newline='') as file:
#             # Assuming all entries have the same keys, so take the keys from the first entry for the header
#             headers = json_data['data'][0].keys()
#             writer = csv.DictWriter(file, fieldnames=headers)
#             writer.writeheader()  # Write the header
#
#             # Iterate over each entry in the data array and write it to the CSV file
#             for entry in json_data['data']:
#                 writer.writerow(entry)
#     else:
#         print("Error: The provided JSON data is missing 'data' key or it's not a list.")
#
# def api_login(spotterId, token, start_date=None, end_date=None):
#     """Fetch data from the Spotter API within a specified date range."""
#     if start_date and end_date:
#         api_url_with_dates = f"https://api.sofarocean.com/api/sensor-data?spotterId={spotterId}&startDate={start_date}&endDate={end_date}&token={token}"
#     else:
#         raise ValueError("Start date and end date must be provided")
#
#     print(f"API URL for Spotter {spotterId}: {api_url_with_dates}")
#
#     response = requests.get(api_url_with_dates)
#
#     if response.status_code == 200:
#         print(f"Successfully fetched data for Spotter {spotterId}.")
#         return response.json()
#     else:
#         print(f"Failed to fetch data for Spotter {spotterId}. Status code: {response.status_code}")
#         raise Exception("API request failed.")
#
#
# def decode_hex_to_ascii(hex_string):
#     """Decode a hex string to ASCII format, handling any Unicode errors gracefully."""
#     byte_value = bytes.fromhex(hex_string)
#     try:
#         return byte_value.decode('utf-8')
#     except UnicodeDecodeError as e:
#         print(f"Error decoding byte: {byte_value[e.start:e.end]} at position {e.start}")
#         return byte_value.decode('utf-8', errors='replace')
#
#
# def save_image(decoded_value, collecting_image_data, image_data, img_directory, image_filename, saved_images_count,
#                timestamp, latitude, longitude, node_id, image_log_path, num_buffers_expected, buffers_received):
#     """Handles collecting image data, skipping filename, timestamp, and length, and saves the image once done."""
#
#     # When a new image starts
#     if '<START IMG>' in decoded_value:
#         # If a new <START IMG> is found and we're collecting data, process the current image
#         if collecting_image_data:
#             print(f"New <START IMG> found before previous image completed. Processing current image with {len(buffers_received)} chunks.")
#             save_image_if_complete(img_directory, timestamp, image_filename, image_data, saved_images_count, latitude, longitude,
#                                    node_id, image_log_path, num_buffers_expected, buffers_received)
#
#         print(f'\nStart image found from node {node_id}.')
#         collecting_image_data = True
#         image_data.clear()
#         buffers_received.clear()  # Reset for the new image
#         num_buffers_expected[0] = 0  # Reset the expected buffer count
#
#         # Extract image filename, timestamp, and length (number of expected buffers)
#         image_info = re.search(r'filename: ([^,]+), timestamp: ([^,]+), length: (\d+)', decoded_value)
#         if image_info:
#             image_filename[0] = image_info.group(1)
#             image_timestamp = image_info.group(2)
#             num_buffers_expected[0] = int(image_info.group(3))
#
#             # Ensure the filename is sanitized and retains its original extension
#             sanitized_file_name = re.sub(r'[^\w\-_\(\)\.]', '_', image_filename[0])
#             if not any(sanitized_file_name.lower().endswith(ext) for ext in [".jpg", ".heic", ".png"]):
#                 sanitized_file_name += ".jpg"  # Default to .jpg if no valid extension is found
#             image_filename[0] = sanitized_file_name
#
#             print(f"Parsed Filename: {image_filename[0]}, Timestamp: {image_timestamp}, Buffers: {num_buffers_expected[0]}")
#         else:
#             print("Warning: Could not parse the message to extract image information.")
#
#     # When receiving image chunks
#     elif collecting_image_data:
#         match = re.search(r'<I(\d+)>', decoded_value)
#         if match:
#             tag_number = int(match.group(1))
#             content = decoded_value[decoded_value.find('>') + 1:]
#             image_data.append((tag_number, content))  # Append as a tuple
#             buffers_received.add(tag_number)  # Track the buffer received using set's add method
#
#         # Check if all expected buffers have been received
#         if len(buffers_received) == num_buffers_expected[0]:
#             print(f"All expected chunks received. Processing image.")
#             save_image_if_complete(img_directory, timestamp, image_filename, image_data, saved_images_count, latitude, longitude,
#                                    node_id, image_log_path, num_buffers_expected, buffers_received)
#             collecting_image_data = False  # Reset after saving the image
#
#     return collecting_image_data
#
# def save_image_if_complete(img_directory, timestamp, image_filename, image_data, saved_images_count, latitude, longitude,
#                            node_id, image_log_path, num_buffers_expected, buffers_received):
#     """
#     Save the image and provide warnings if buffers are missing.
#     Use JSON timestamp for file name while preserving correct file extension.
#     """
#
#     # Check for missing buffers
#     expected_buffers = set(range(num_buffers_expected[0]))  # Full set of expected buffers
#     missing_buffers = sorted(list(expected_buffers - buffers_received))  # Calculate missing buffers
#
#     if missing_buffers:
#         print(f"Warning: Missing chunks. Received {len(buffers_received)} out of {num_buffers_expected[0]}.")
#         print(f"Missing chunks: {missing_buffers}")
#         # Proceed to save the image with a warning about missing buffers
#
#     if image_data:
#         # Sort based on buffer index to reconstruct the image in the correct order
#         image_data.sort(key=lambda x: x[0])
#         cleaned_base64_data = "".join([data for _, data in image_data])
#
#         try:
#             # Decode the base64-encoded image data
#             decoded_data = base64.b64decode(cleaned_base64_data)
#
#             if not os.path.exists(img_directory):
#                 os.makedirs(img_directory)
#
#             # Generate file name based on JSON timestamp with the correct file extension
#             file_extension = os.path.splitext(image_filename[0])[1].lower()
#             formatted_timestamp = timestamp.replace(':', '-').replace('T', '_').split('.')[0]
#             sanitized_file_name = f"{formatted_timestamp}_image{file_extension}"
#             file_path = os.path.join(img_directory, sanitized_file_name)
#
#             # Save the image file
#             with open(file_path, 'wb') as file:
#                 file.write(decoded_data)
#
#             file_size = os.path.getsize(file_path)
#             print(f"Image saved successfully at {file_path}, File Size: {file_size} bytes")
#
#             # Update saved images count
#             saved_images_count[0] += 1
#
#             # Log image details
#             with open(image_log_path, mode='a', newline='') as file:
#                 writer = csv.writer(file)
#                 writer.writerow([timestamp, latitude, longitude, node_id, sanitized_file_name, file_size])
#
#         except base64.binascii.Error as b64_error:
#             print(f"Base64 decoding failed: {b64_error}")
#         except Exception as e:
#             print(f"Error saving image: {e}")
#     else:
#         print("Warning: No image data collected to save.")
#
# def log_image(image_log_path, timestamp, latitude, longitude, node_id, file_path):
#     """Logs image data into the image log CSV file."""
#     file_size = os.path.getsize(file_path)
#     with open(image_log_path, mode='a', newline='') as file:
#         writer = csv.writer(file)
#         writer.writerow([timestamp, latitude, longitude, node_id, file_path, file_size])
#
#
# def process_json(json_data, img_directory_base):
#     """Splits data by bristlemouth_node_id and saves separate CSV files in subfolders."""
#
#     # Step 1: Create a main directory for this API call
#     if not os.path.exists(img_directory_base):
#         os.makedirs(img_directory_base)
#
#     # Step 2: Group data by bristlemouth_node_id using a defaultdict
#     grouped_data = defaultdict(list)
#
#     # Step 3: Loop through each entry in the JSON data and group by node_id
#     for entry in json_data['data']:
#         node_id = entry['bristlemouth_node_id']
#         grouped_data[node_id].append(entry)
#
#     # Step 4: Create subfolders and CSV files for each node_id (only in this function)
#     for node_id, entries in grouped_data.items():
#         # Create subfolder for this node_id
#         node_directory = os.path.join(img_directory_base, f"{node_id}")
#         if not os.path.exists(node_directory):
#             os.makedirs(node_directory)
#
#         # Define the CSV file path
#         csv_filename = os.path.join(node_directory, f"{node_id}.csv")
#
#         # Check if there's any data in the first entry to get the headers
#         if len(entries) > 0:
#             headers = entries[0].keys()
#         else:
#             continue  # Skip if no entries for the node
#
#         # Write data to CSV for each bristlemouth_node_id
#         with open(csv_filename, mode='w', newline='') as csv_file:
#             writer = csv.DictWriter(csv_file, fieldnames=headers)
#
#             # Write the header
#             writer.writeheader()
#
#             # Write the data rows
#             for entry in entries:
#                 writer.writerow(entry)
#
#         print(f"Data for node {node_id} saved to {csv_filename}")
#
#     return grouped_data  # Return grouped data to be used in the next function
#
# def process_grouped_data(grouped_data, img_directory_base, csv_path, image_log_path):
#     """Processes grouped data entries (sorted by bristlemouth_node_id) to extract image and text data."""
#
#     total_images_saved = 0
#
#     for node_id, entries in grouped_data.items():
#         print(f"Processing bristlemouth_node_id: {node_id}")
#
#         # Create a single directory for each bristlemouth_node_id without the "node_" prefix
#         node_img_directory = os.path.join(img_directory_base, f"{node_id}")
#         if not os.path.exists(node_img_directory):
#             os.makedirs(node_img_directory)
#
#         collecting_image_data = False
#         image_data = []
#         image_filename = [None]
#         saved_images_count = [0]
#         buffers_received = set()
#         num_buffers_expected = [0]
#
#         node_csv_path = os.path.join(node_img_directory, f"{node_id}.csv")
#
#         # Write text data for this node
#         with open(node_csv_path, mode='w', newline='') as csv_file:
#             writer = csv.DictWriter(csv_file, fieldnames=['timestamp', 'latitude', 'longitude', 'decoded_value'])
#             writer.writeheader()
#
#             for entry in entries:
#                 decoded_value = decode_hex_to_ascii(entry['value'])
#                 latitude = entry['latitude']
#                 longitude = entry['longitude']
#                 timestamp = entry['timestamp']  # Extract the timestamp from the JSON
#
#                 writer.writerow({
#                     'timestamp': timestamp,
#                     'latitude': latitude,
#                     'longitude': longitude,
#                     'decoded_value': decoded_value
#                 })
#
#                 # Pass the timestamp to the save_image function
#                 collecting_image_data = save_image(
#                     decoded_value, collecting_image_data, image_data, node_img_directory, image_filename,
#                     saved_images_count, timestamp, latitude, longitude, node_id, image_log_path,
#                     num_buffers_expected, buffers_received
#                 )
#
#         print(f"Images saved for node {node_id}: {saved_images_count[0]}")
#         total_images_saved += saved_images_count[0]
#
#     print(f"Total images saved across all node IDs: {total_images_saved}")
#
#
# def main_hardcode():
#     # Define a list of Spotter IDs to process
#     spotter_ids = ["SPOT-31593C", "SPOT-31081C"]  # Add as many IDs as needed
#
#     # Define the start and end dates for API calls
#     start_date = "2025-06-09T00:00:00Z"
#     end_date = "2025-06-11T00:00:00Z"
#
#     for spotter_id in spotter_ids:
#         print(f"\nProcessing Spotter ID: {spotter_id}")
#
#         try:
#             # Fetch API data for the current Spotter ID
#             api_data = api_login(spotter_id, start_date=start_date, end_date=end_date)
#
#             # Create a directory for this Spotter ID
#             spotter_img_directory = os.path.join(img_directory, spotter_id)
#             if not os.path.exists(spotter_img_directory):
#                 os.makedirs(spotter_img_directory)
#
#             # Step 1: Process the JSON and get the grouped data
#             grouped_data = process_json(api_data, spotter_img_directory)
#
#             # Step 2: Use the grouped data to process the images and text data
#             process_grouped_data(grouped_data, spotter_img_directory, csv_path, image_log_path)
#
#             # Step 3: Save all JSON data from API call to CSV
#             json_to_csv(csv_path, api_data)
#
#         except Exception as e:
#             print(f"Error processing Spotter ID {spotter_id}: {e}")
#
# def main(spotter_ids, start_date, end_date, token):
#     for spotter_id in spotter_ids:
#         print(f"\nProcessing Spotter ID: {spotter_id}")
#         try:
#             api_data = api_login(spotter_id, token=token, start_date=start_date, end_date=end_date)
#
#             spotter_img_directory = os.path.join(img_directory, spotter_id)
#             os.makedirs(spotter_img_directory, exist_ok=True)
#
#             grouped_data = process_json(api_data, spotter_img_directory)
#             process_grouped_data(grouped_data, spotter_img_directory, csv_path, image_log_path)
#             json_to_csv(csv_path, api_data)
#
#         except Exception as e:
#             print(f"Error processing Spotter ID {spotter_id}: {e}")
#
# # if using hardcode method
# # if __name__ == "__main__":
# #     main()
# if __name__ == "__main__":
#     parser = argparse.ArgumentParser(description="Fetch and process Spotter API image data.")
#     parser.add_argument('--spotters', nargs='+', default=["SPOT-31593C"], help='List of Spotter IDs')
#     parser.add_argument('--start', default="2025-05-18T00:00:00Z", help='Start date in ISO format')
#     parser.add_argument('--end', default="2025-05-20T00:00:00Z", help='End date in ISO format')
#     parser.add_argument('--token', default="add_your_key_here", help='You API token')
#
#     args = parser.parse_args()
#     main(args.spotters, args.start, args.end, args.token)
#


#### ChatGPT suggestion for whole script change

# filename: sofar_api_image_pull.py
# description: parse the data from API and save images + CSV file with summary of lat, lon, filename, and message
#
# Copyright 2025 Nick Raymond
# Licensed under the Apache License, Version 2.0

import argparse
import os
import re
import base64
import requests
import csv
from collections import defaultdict

# -----------------------------
# Config
# -----------------------------
IMG_ROOT = 'parsed_images'
CSV_FILENAME = 'spotter_data.csv'
IMAGE_LOG_FILENAME = 'spotter_image_log.csv'
ALLOWED_EXTS = (".jpg", ".jpeg", ".heic", ".png")

# START-line metadata patterns (any order), tolerant of '-flag' before extension
# Example: <START IMG> filename: 2025-08-30T05:24:01Z_image-c.heic, chunks: 5
RE_FILENAME = re.compile(
    r'filename\s*[:=]\s*"?([^\s,"]+?)"?\s*(?:,|$)', re.IGNORECASE
)
RE_CHUNKS = re.compile(
    r'(?:chunks|length|len|buffers?)\s*[:=]\s*(\d+)', re.IGNORECASE
)
# ISO timestamp embedded in filename before '_image'
RE_TS_IN_NAME = re.compile(
    r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)_image', re.IGNORECASE
)

# Ensure root dirs/files exist
os.makedirs(IMG_ROOT, exist_ok=True)
csv_path = os.path.join(IMG_ROOT, CSV_FILENAME)
image_log_path = os.path.join(IMG_ROOT, IMAGE_LOG_FILENAME)
if not os.path.exists(csv_path):
    with open(csv_path, mode='w', newline='') as f:
        csv.writer(f).writerow(["Timestamp", "Latitude", "Longitude", "Node ID", "Decoded Value"])
if not os.path.exists(image_log_path):
    with open(image_log_path, mode='w', newline='') as f:
        csv.writer(f).writerow(["Timestamp", "Latitude", "Longitude", "Node ID", "Filename", "File Size (bytes)"])

# -----------------------------
# Helpers
# -----------------------------
def json_to_csv(out_csv_path, json_data):
    data = json_data.get('data', [])
    if isinstance(data, list) and data:
        with open(out_csv_path, mode='w', newline='') as f:
            headers = data[0].keys()
            w = csv.DictWriter(f, fieldnames=headers)
            w.writeheader()
            for entry in data:
                w.writerow(entry)
    else:
        print("Error: The provided JSON has no 'data' list.")

def api_login(spotter_id, token, start_date=None, end_date=None):
    if start_date and end_date:
        api_url = (f"https://api.sofarocean.com/api/sensor-data?"
                   f"spotterId={spotter_id}&startDate={start_date}&endDate={end_date}&token={token}")
    else:
        raise ValueError("Start date and end date must be provided")
    print(f"API URL for Spotter {spotter_id}: {api_url}")
    r = requests.get(api_url)
    if r.status_code == 200:
        print(f"Successfully fetched data for Spotter {spotter_id}.")
        return r.json()
    print(f"Failed to fetch data for Spotter {spotter_id}. Status code: {r.status_code}")
    raise Exception("API request failed.")

def decode_hex_to_ascii(hex_string):
    b = bytes.fromhex(hex_string)
    try:
        return b.decode('utf-8')
    except UnicodeDecodeError as e:
        print(f"Error decoding byte: {b[e.start:e.end]} at position {e.start}")
        return b.decode('utf-8', errors='replace')

def normalize_filename_flag(name):
    """
    Remove an optional '-<flag>' inserted right before the extension.
    e.g., 2025-..._image-c.heic -> 2025-..._image.heic
    """
    if not name:
        return None
    base, ext = os.path.splitext(name)
    base = re.sub(r'(?<=_image)-[A-Za-z0-9]+$', '', base)  # drop trailing -flag after _image
    if ext.lower() not in ALLOWED_EXTS:
        ext = ".jpg"
    return f"{base}{ext}"

def parse_start_metadata(text):
    """
    Parse filename and chunk count from a START line (any order).
    Returns (filename_normalized, ts_in_filename_or_None, expected_chunks_or_0).
    """
    fname = None
    chunks = 0

    mfn = RE_FILENAME.search(text)
    if mfn:
        fname = normalize_filename_flag(mfn.group(1))

    mck = RE_CHUNKS.search(text)
    if mck:
        chunks = int(mck.group(1))

    its = None
    if fname:
        mts = RE_TS_IN_NAME.search(fname)
        if mts:
            its = mts.group(1)

    return fname, its, chunks

def base64_clean(s):
    s = re.sub(r'[^A-Za-z0-9+/=]', '', s or '')
    pad = (-len(s)) % 4
    if pad:
        s += "=" * pad
    return s

def sniff_ext_from_bytes(data: bytes):
    try:
        if data.startswith(b'\xff\xd8\xff'):
            return ".jpg"
        if data.startswith(b'\x89PNG\r\n\x1a\n'):
            return ".png"
        # Quick HEIC/HEIF sniff (ISO-BMFF brands)
        if len(data) >= 32 and b'ftyp' in data[4:12]:
            brands = data[8:32]
            if any(x in brands for x in (b'heic', b'heix', b'hevc', b'heif', b'mif1', b'msf1', b'avif')):
                return ".heic"
    except Exception:
        pass
    return None

def log_image(image_log_path, timestamp, latitude, longitude, node_id, filename, file_size):
    with open(image_log_path, mode='a', newline='') as f:
        csv.writer(f).writerow([timestamp, latitude, longitude, node_id, filename, file_size])

# -----------------------------
# Image assembly
# -----------------------------
def save_image(decoded_value, collecting, image_chunks, img_dir, image_filename, saved_count,
               timestamp, latitude, longitude, node_id, image_log_path, num_expected, end_seen):
    """
    Robust handler for START -> chunks -> END. Tolerates missing metadata and out-of-order chunks.
    - image_chunks: dict[index] = base64_str (keep longest per index)
    - num_expected[0]: expected unique chunks (0 if unknown)
    - end_seen[0]: whether we've seen an END for the current image
    """

    # START
    if '<START IMG>' in decoded_value:
        if collecting and image_chunks:
            print(f"New <START IMG> before previous completed. Flushing partial with {len(image_chunks)} chunks.")
            save_image_if_complete(img_dir, timestamp, image_filename, image_chunks, saved_count,
                                   latitude, longitude, node_id, image_log_path, num_expected)
        print(f'\nStart image found from node {node_id}.')
        collecting = True
        image_chunks.clear()
        num_expected[0] = 0
        end_seen[0] = False
        image_filename[0] = None

        # Parse metadata on START line
        fname, its, chunks = parse_start_metadata(decoded_value)
        if fname:
            image_filename[0] = fname
        if chunks:
            num_expected[0] = chunks
        if fname or chunks:
            print(f"Parsed START metadata: filename={image_filename[0]} chunks={num_expected[0]} ts_in_name={its}")
        else:
            print("Note: No metadata on START line; will look for it subsequently.")
        return collecting

    # While collecting
    if collecting:
        # Late metadata lines (catch filename/chunks if they arrive later)
        if (image_filename[0] is None) or (num_expected[0] == 0):
            fname, its, chunks = parse_start_metadata(decoded_value)
            changed = False
            if fname and image_filename[0] is None:
                image_filename[0] = fname
                changed = True
            if chunks and num_expected[0] == 0:
                num_expected[0] = chunks
                changed = True
            if changed:
                print(f"Parsed late metadata: filename={image_filename[0]} chunks={num_expected[0]} ts_in_name={its}")

        # END (don’t flush immediately if we still lack chunks)
        if '<END IMG>' in decoded_value:
            end_seen[0] = True
            have = len(image_chunks)
            need = num_expected[0]
            if need > 0 and have >= need:
                print("END seen and all expected chunks present; saving.")
                save_image_if_complete(img_dir, timestamp, image_filename, image_chunks, saved_count,
                                       latitude, longitude, node_id, image_log_path, num_expected)
                return False  # collecting off
            else:
                # Keep collecting; we’ll flush when we reach 'need', or at next START, or at end-of-stream.
                print(f"END seen but not complete yet (have {have}, need {need or 'unknown'}). Continuing to collect.")
                return True

        # Chunk lines
        m = re.search(r'<I(\d+)>', decoded_value)
        if m:
            idx = int(m.group(1))
            raw = decoded_value[decoded_value.find('>') + 1:]
            content = base64_clean(raw)
            prev = image_chunks.get(idx)
            if (prev is None) or (len(content) > len(prev)):
                image_chunks[idx] = content

            # If we now have all expected chunks and END was already seen, save.
            if num_expected[0] > 0 and len(image_chunks) >= num_expected[0] and end_seen[0]:
                print(f"Collected all expected chunks ({num_expected[0]}) after END; saving.")
                save_image_if_complete(img_dir, timestamp, image_filename, image_chunks, saved_count,
                                       latitude, longitude, node_id, image_log_path, num_expected)
                return False

    return collecting

def save_image_if_complete(img_dir, timestamp, image_filename, image_chunks, saved_count, latitude,
                           longitude, node_id, image_log_path, num_expected):
    """
    Save whatever we have (partial or full). Use timestamp-based name if filename missing.
    Decide correct extension by sniffing content if necessary.
    """
    if not image_chunks:
        print("Warning: No image data collected to save.")
        return

    have = len(image_chunks)
    need = num_expected[0]
    if need > 0 and have < need:
        print(f"Warning: Missing chunks. Received {have} of {need}.")

    # Build base64 in order of indices
    cleaned = "".join(image_chunks[k] for k in sorted(image_chunks.keys()))
    cleaned = base64_clean(cleaned)

    # Choose filename & extension (prefer parsed ext, otherwise sniff)
    parsed_ext = None
    if image_filename[0]:
        parsed_ext = os.path.splitext(image_filename[0])[1].lower()
        if parsed_ext not in ALLOWED_EXTS:
            parsed_ext = None

    # Fallback timestamp for final name
    ts = (timestamp or "unknown_time").replace(':', '-').replace('T', '_').split('.')[0]
    out_name = f"{ts}_image{parsed_ext or '.jpg'}"
    out_path = os.path.join(img_dir, out_name)
    os.makedirs(img_dir, exist_ok=True)

    try:
        decoded = base64.b64decode(cleaned, validate=False)
        if not decoded:
            print("Decoded data is empty; skipping save.")
            return

        # Sniff true type and fix extension if needed
        sniff = sniff_ext_from_bytes(decoded)
        final_ext = sniff or parsed_ext or ".jpg"
        if not out_name.endswith(final_ext):
            out_name = f"{ts}_image{final_ext}"
            out_path = os.path.join(img_dir, out_name)

        with open(out_path, 'wb') as f:
            f.write(decoded)

        size = os.path.getsize(out_path)
        print(f"Image saved at {out_path}, File Size: {size} bytes")

        saved_count[0] += 1
        log_image(image_log_path, timestamp, latitude, longitude, node_id, out_name, size)

    except Exception as e:
        print(f"Error saving image: {e}")

# -----------------------------
# Data processing
# -----------------------------
def process_json(json_data, img_dir_base):
    os.makedirs(img_dir_base, exist_ok=True)

    grouped = defaultdict(list)
    for entry in json_data.get('data', []):
        node_id = entry.get('bristlemouth_node_id')
        if node_id is None:
            continue
        grouped[node_id].append(entry)

    # Write raw group CSVs for reference
    for node_id, entries in grouped.items():
        node_dir = os.path.join(img_dir_base, f"{node_id}")
        os.makedirs(node_dir, exist_ok=True)
        csv_filename = os.path.join(node_dir, f"{node_id}.csv")
        if entries:
            headers = entries[0].keys()
            with open(csv_filename, mode='w', newline='') as f:
                w = csv.DictWriter(f, fieldnames=headers)
                w.writeheader()
                for entry in entries:
                    w.writerow(entry)
            print(f"Data for node {node_id} saved to {csv_filename}")

    return grouped

def process_grouped_data(grouped, img_dir_base, csv_path, image_log_path):
    total_images_saved = 0

    for node_id, entries in grouped.items():
        print(f"Processing bristlemouth_node_id: {node_id}")
        node_img_dir = os.path.join(img_dir_base, f"{node_id}")
        os.makedirs(node_img_dir, exist_ok=True)

        # Sort by the JSON timestamp to reduce out-of-order issues
        entries_sorted = sorted(entries, key=lambda e: e.get('timestamp', ''))

        collecting = False
        image_chunks = {}              # idx -> base64 string
        image_filename = [None]        # parsed filename (normalized) if available
        saved_images_count = [0]
        num_expected = [0]             # expected unique chunk count
        end_seen = [False]             # whether END has been seen

        node_csv_path = os.path.join(node_img_dir, f"{node_id}.csv")
        with open(node_csv_path, mode='w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=['timestamp', 'latitude', 'longitude', 'decoded_value'])
            w.writeheader()

            last_lat = last_lon = None
            last_ts = None

            for entry in entries_sorted:
                decoded_value = decode_hex_to_ascii(entry.get('value', ''))
                latitude = entry.get('latitude')
                longitude = entry.get('longitude')
                timestamp = entry.get('timestamp')

                last_lat, last_lon, last_ts = latitude, longitude, timestamp
                w.writerow({'timestamp': timestamp, 'latitude': latitude, 'longitude': longitude, 'decoded_value': decoded_value})

                collecting = save_image(
                    decoded_value, collecting, image_chunks, node_img_dir, image_filename,
                    saved_images_count, timestamp, latitude, longitude, node_id, image_log_path,
                    num_expected, end_seen
                )

            # End-of-stream flush (partial or complete)
            if collecting and image_chunks:
                print("End of entries; flushing current image.")
                save_image_if_complete(node_img_dir, last_ts, image_filename, image_chunks, saved_images_count,
                                       last_lat, last_lon, node_id, image_log_path, num_expected)
                collecting = False

        print(f"Images saved for node {node_id}: {saved_images_count[0]}")
        total_images_saved += saved_images_count[0]

    print(f"Total images saved across all node IDs: {total_images_saved}")

# -----------------------------
# Entrypoints
# -----------------------------
def main_hardcode():
    spotter_ids = ["SPOT-31593C", "SPOT-31081C"]
    start_date = "2025-06-09T00:00:00Z"
    end_date = "2025-06-11T00:00:00Z"
    token = "add_your_key_here"

    for spotter_id in spotter_ids:
        print(f"\nProcessing Spotter ID: {spotter_id}")
        try:
            api_data = api_login(spotter_id, token=token, start_date=start_date, end_date=end_date)
            spotter_img_dir = os.path.join(IMG_ROOT, spotter_id)
            os.makedirs(spotter_img_dir, exist_ok=True)
            grouped = process_json(api_data, spotter_img_dir)
            process_grouped_data(grouped, spotter_img_dir, csv_path, image_log_path)
            json_to_csv(csv_path, api_data)
        except Exception as e:
            print(f"Error processing Spotter ID {spotter_id}: {e}")

def main(spotter_ids, start_date, end_date, token):
    for spotter_id in spotter_ids:
        print(f"\nProcessing Spotter ID: {spotter_id}")
        try:
            api_data = api_login(spotter_id, token=token, start_date=start_date, end_date=end_date)
            spotter_img_dir = os.path.join(IMG_ROOT, spotter_id)
            os.makedirs(spotter_img_dir, exist_ok=True)
            grouped = process_json(api_data, spotter_img_dir)
            process_grouped_data(grouped, spotter_img_dir, csv_path, image_log_path)
            json_to_csv(csv_path, api_data)
        except Exception as e:
            print(f"Error processing Spotter ID {spotter_id}: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch and process Spotter API image data.")
    parser.add_argument('--spotters', nargs='+', default=["SPOT-31593C"], help='List of Spotter IDs')
    parser.add_argument('--start', default="2025-05-18T00:00:00Z", help='Start date in ISO format')
    parser.add_argument('--end', default="2025-05-20T00:00:00Z", help='End date in ISO format')
    parser.add_argument('--token', default="add_your_key_here", help='Your API token')
    args = parser.parse_args()
    main(args.spotters, args.start, args.end, args.token)
