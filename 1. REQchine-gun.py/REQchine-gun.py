# --------------------
# Work in progress
# --------------------

# Phase 1 : Packet Constructor and Forwarder
# -> Extract packet's contents from FILE
# -> Construct NEW packet
# -> Send the packet
# Phase 1 - Completed

# Phase 2 : Replacement target(s) Detector and Replacer
# -> Accept a single wordlist or a pathlist
# -> A pathlist is a basically a file containing the paths of multiple wordlists.
# -> Determine the number of replacement targets based on the provided wordlist or pathlist.
# -> If a wordlist has been provided then only one target would be present.
# -> If a pathlist has been provided then multiple targets would be present (Must have a target counter in the code). 
# -> Detect the replacement targets after the parsing stage.
# -> In case of a POST request, update the Content-Length header after the replacement(s)
# Format for paceholder: ^REQchine^
# Phase 2 (Single replacement target) - Completed

#Phase 3: Forwarder for the updated requests and Response Collector
# -> Forward the packets to the target after the needed replacements have been performed.
# -> Collect the responses received from the target.


import argparse
import copy
import requests

PLACEHOLDER_TEXT = "^REQchine^"
PLACEHOLDER_TEXT_BINARY = b"^REQchine^"
RESPONSE_LIST = []

def parse_arguments():
    parser = argparse.ArgumentParser(description="Rapidly fires customized HTTP requests at the pointed target!")
    parser.add_argument('-r', '--request', type=str, required=True, help='File containing the HTTP request packet')
    parser.add_argument('-w', '--wordlist', type=str, help='A Wordlist containing the words to be used as replacements in the HTTP requests')
    parser.add_argument('-p', '--pathlist', type=str, help='A Pathlist containing the paths of various wordlists to be used. The first wordlist would be used for the first target, the second wordlist for the second target and so on.')
    parser.add_argument('-v', '--verbose', action='store_true', help='For Verbose Output')
    

    return parser

def check_arguments(args, parser):

    if args.wordlist is None and args.pathlist is None:
        parser.error("No wordlist or pathlist provided. You must supply a --wordlist or a --pathlist for the tool to work correctly.")
    
    if args.wordlist and args.pathlist:
        parser.error("Both --wordlist and --pathlist have been provided. You must supply only one of the two arguments for the tool to work correctly.")


def get_replacements_count_and_filepaths(args):
    
    replacements_filepaths = []

    if args.wordlist:
        replacements_count = 1
        replacements_filepaths.append(args.wordlist)
    else:
        try:
            with open(args.pathlist, 'r') as file:
                file_content = file.read()
                replacements_filepaths = file_content.splitlines()
                replacements_count = len(replacements_filepaths)
        except FileNotFoundError:
            print(f"Error: The file '{args.pathlist}' was not found.")
            exit(1)
        except Exception as e:
            print(f"Error: {e}")
            exit(1)
    
    return replacements_count, replacements_filepaths


def print_verbose_output(args):
    #print(args.verbose)
    if args.verbose:
        print("Verbose mode enabled")
        print(f"HTTP Request File: {args.request}")
        # Future Work:
        # if args.output:
        #     print(f"Output file: {args.output}")

    

def extract_packet_sections(path):
    try:
        with open(path, 'rb') as file:
            
            # Request line extraction
            
            btext = file.readline()
            if btext.endswith(b'\r\n'):
                btext = btext[:-2]
            packet_req_line = btext.decode('utf-8')
 
            # Headers extraction
            
            packet_headers = []
            
            while True:
                btext = file.readline()
                if btext != b'\r\n':
                    if btext.endswith(b'\r\n'):
                        btext = btext[:-2]
                    packet_headers.append(btext.decode('utf-8'))
                else:
                    break

            # Body extraction

            packet_body = file.read()
            return packet_req_line, packet_headers, packet_body

    except FileNotFoundError:
        print(f"Error: The file '{path}' was not found.")
        exit(1)
    except Exception as e:
        print(f"Error: {e}")
        exit(1)
    

def print_packet_sections(request_line, headers, body):
    print("Req Line : ", request_line)
    print("-------Headers--------")
    print(headers)
    print("---------Body---------")
    if body:
        print(body)
    else:
        print("None")

def parse_request_line(request_line):
    req_line_segments = request_line.split()
    req_line_obj = {}
    req_line_obj["method"] = req_line_segments[0]
    req_line_obj["target"] = req_line_segments[1]
    req_line_obj["version"] = req_line_segments[2]

    return req_line_obj

def parse_headers(headers):
    header_obj = {}
    for raw_header in headers:
        head_val = raw_header.split(': ', 1)
        header_obj[head_val[0]] = head_val[1]
    return header_obj


def build_and_send_packet(req_line, headers, req_body):
    print("Reached here")
    URL = "http://" + headers["Host"] + req_line["target"]
    print("Reached here too")
    host_header_val = headers["Host"]
    del headers["Host"]
    if req_line["method"] == "GET":
        response = requests.get(URL, headers=headers)
        headers["Host"] = host_header_val
        return response
        #print("Response Status Code : ", response.status_code)
    
    elif req_line["method"] == "POST":
        response = requests.post(URL, headers=headers, data=req_body)
        headers["Host"] = host_header_val
        return response
        #print("Response Status Code : ", response.status_code)
    else:
        print("The tool only supports GET/POST requests, as of now.")
        exit(0)


def handle_single_replacement_in_req_line(req_line_obj, headers, req_body, wl_file):
    try:
        with open(wl_file) as wordlist_file:
            print(req_line_obj)
            original_target = req_line_obj["target"]
            print("------------")
            
            for word in wordlist_file:
                replacement = word.strip()
                req_line_obj["target"] = req_line_obj["target"].replace(PLACEHOLDER_TEXT, replacement, 1)
                print(req_line_obj)
                
                RESPONSE_LIST.append(build_and_send_packet(req_line_obj, headers, req_body))
                
                req_line_obj["target"] = original_target
            
            print(RESPONSE_LIST)
            print(len(RESPONSE_LIST))

    except FileNotFoundError:
        print(f"Error: The file '{wl_file}' was not found.")
        exit(1)
    except Exception as e:
        print(f"Error: {e}")
        exit(1)


def handle_single_replacement_in_header(req_line_obj, header_obj, req_body, header, value, wl_file):
    try:
        with open(wl_file) as wordlist_file:
            print(f"{header} : {value}")
            print("------------")
            for word in wordlist_file:
                replacement = word.strip()
                header_obj[header] = header_obj[header].replace(PLACEHOLDER_TEXT, replacement, 1)
                print(f"{header} : {header_obj[header]}")
                RESPONSE_LIST.append(build_and_send_packet(req_line_obj, header_obj, req_body))
                header_obj[header] = value
            
            print(RESPONSE_LIST)
            print(len(RESPONSE_LIST))

    except FileNotFoundError:
        print(f"Error: The file '{wl_file}' was not found.")
        exit(1)
    except Exception as e:
        print(f"Error: {e}")
        exit(1)


def handle_single_replacement_in_req_body(req_line_obj, header_obj, req_body, wl_file):
    try:
        with open(wl_file) as wordlist_file:
            print(f"Req body's length BEFORE update : {len(req_body)}")
            print(f"Content-Length : {header_obj["Content-Length"]}")                    
            print("------------")
            for word in wordlist_file:
                replacement = word.strip().encode()
                modified_req_body = req_body.replace(PLACEHOLDER_TEXT_BINARY, replacement, 1)
                header_obj["Content-Length"] = str(len(modified_req_body))
                if len(modified_req_body) < 150:
                    print(modified_req_body)
                print(f"Req body's length AFTER update : {len(modified_req_body)}")
                print(f"Content-Length : {header_obj["Content-Length"]}")
                RESPONSE_LIST.append(build_and_send_packet(req_line_obj, header_obj, modified_req_body))
            
            print(RESPONSE_LIST)
            print(len(RESPONSE_LIST))

    except FileNotFoundError:
        print(f"Error: The file '{wl_file}' was not found.")
        exit(1)
    except Exception as e:
        print(f"Error: {e}")
        exit(1)


def make_replacements_and_fire_the_gun(req_filepath, r_count, r_filepaths, req_line_obj, header_obj, req_body):
    if r_count == 1:
        #---------------------------
        # Find the replacement target in the packet
        # Open the wordlist and call build_and_send_packet() for every word in the wordlist and obtain the response object.
        # Populate the keys stats of the returned response object
        # Have a mechanism to pause or end the requests firing
        #---------------------------

        # Check for the PLACEHOLDER_TEXT in req_line_obj

        if PLACEHOLDER_TEXT in req_line_obj["target"]:
            handle_single_replacement_in_req_line(req_line_obj, header_obj, req_body, r_filepaths[0])
            return

        # Check for the PLACEHOLDER_TEXT in header_obj

        for header, value in header_obj.items():
            if PLACEHOLDER_TEXT in value:
                handle_single_replacement_in_header(req_line_obj, header_obj, req_body, header, value, r_filepaths[0])
                
                return

        # Check for the PLACEHOLDER_TEXT in req_body

        if req_line_obj["method"] != "POST":
            print(f"Error: No replacement target (^REQchine^) was found in the provided request file '{req_filepath}'. Check your file!")
            exit(1)
        else:
            if PLACEHOLDER_TEXT_BINARY in req_body:
                handle_single_replacement_in_req_body(req_line_obj, header_obj, req_body, r_filepaths[0])

            else:
                print(f"Error: No replacement target (^REQchine^) was found in the provided request file '{req_filepath}'. Check your file!")
                exit(1)


def main():
    
    # Argument parsing and dealing with verbose O/p

    parser = parse_arguments()
    args = parser.parse_args()
    check_arguments(args, parser)
    replacements_count, replacements_filepaths = get_replacements_count_and_filepaths(args)
    print(replacements_count)
    print(replacements_filepaths)
    print_verbose_output(args)
    

    # Extraction of the packet's sections

    packet_req_line, packet_headers, packet_body = extract_packet_sections(args.request)
    #print_packet_sections(packet_req_line, packet_headers, packet_body)
    #print(packet_body)

    # Parsing of the packet's sections
    
    req_line_obj = parse_request_line(packet_req_line)
    print(req_line_obj)
    header_obj = parse_headers(packet_headers)
    #print(header_obj)
    
    # i = 1
    # for k, v in header_obj.items():
    #     print(f"{i}. {k}::: {v}")
    #     i += 1
    
    #print(len(packet_body))
    #print(packet_body)
    #print(len(packet_body))
    
    req_body = packet_body if packet_body else None
    
    #print(req_body)
    #print(len(req_body))
    #print_packet_sections(req_line_obj, header_obj, req_body)
    

    # The core functionality

    make_replacements_and_fire_the_gun(args.request, replacements_count, replacements_filepaths, req_line_obj, header_obj, req_body)
    
    #exit(0)
    # Building and Sending the packet
    
    #build_and_send_packet(req_line_obj, header_obj, req_body)


if __name__ == "__main__":
    main()