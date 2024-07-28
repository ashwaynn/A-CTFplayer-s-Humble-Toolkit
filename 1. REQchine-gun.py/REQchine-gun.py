# --------------------
# Work in progress
# --------------------

# Phase 1 : Packet Constructor and Forwarder
# -> extract packet's contents from FILE
# -> construct NEW packet
# -> Send the packet

import argparse

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

def read_file(path):
    try:
        with open(path, 'r') as file:
            content = file.read()
        return content
    except FileNotFoundError:
        print(f"Error: The file '{path}' was not found.")
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None

def extract_packet_sections(file_content):
    lines = file_content.splitlines()
    
    # Request line extraction
    packet_req_line = lines[0]
    
    # Headers extraction
    packet_headers = []
    empty_line_index = 0
    for i in range(1, len(lines)):
        if lines[i].strip() != '':
            packet_headers.append(lines[i])
        else:
            empty_line_index = i
            break

    # Body extraction
    if empty_line_index + 1 < len(lines):
        # HTTP request has a body
        packet_body = lines[empty_line_index+1:len(lines)]
    else:
        packet_body = None

    return packet_req_line, packet_headers, packet_body

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

def main():
    args = parse_arguments()
    print_verbose_output(args)
    file_content = read_file(args.request)
    packet_req_line, packet_headers, packet_body = extract_packet_sections(file_content)
    #print_packet_sections(packet_req_line, packet_headers, packet_body)
    req_line_obj = parse_request_line(packet_req_line)
    print(req_line_obj)
    header_obj = parse_headers(packet_headers)
    #print(header_obj)
    i = 1
    for k, v in header_obj.items():
        print(f"{i}. {k}::: {v}")
        i += 1


if __name__ == "__main__":
    main()