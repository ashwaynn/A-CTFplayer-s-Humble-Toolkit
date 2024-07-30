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
# -> Detect the replacement target during the parsing stage.
# -> In case of a POST request, update the Content-Length header after the replacement(s)



import argparse
import requests

def parse_arguments():
    parser = argparse.ArgumentParser(description="Rapidly fires customized HTTP requests at the pointed target!")
    parser.add_argument('-r', '--request', type=str, required=True, help='File containing the HTTP request packet')
    parser.add_argument('-v', '--verbose', action='store_true', help='For Verbose Output')

    return parser.parse_args()

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
    URL = "http://" + headers["Host"] + req_line["target"]
    del headers["Host"]
    if req_line["method"] == "GET":
        response = requests.get(URL, headers=headers)
        print("Response Status Code : ", response.status_code)
    
    elif req_line["method"] == "POST":
        response = requests.post(URL, headers=headers, data=req_body)
        print("Response Status Code : ", response.status_code)
    else:
        print("The tool only supports GET/POST requests, as of now.")
        exit(0)



def main():
    
    # Argument parsing and dealing with verbose O/p

    args = parse_arguments()
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
    
    i = 1
    for k, v in header_obj.items():
        print(f"{i}. {k}::: {v}")
        i += 1
    
    #print(len(packet_body))
    #print(packet_body)
    print(len(packet_body))
    req_body = packet_body if packet_body else None
    #print(req_body)
    #print(len(req_body))
    #print_packet_sections(req_line_obj, header_obj, req_body)
    
    
    # Building and Sending the packet
    
    build_and_send_packet(req_line_obj, header_obj, req_body)


if __name__ == "__main__":
    main()