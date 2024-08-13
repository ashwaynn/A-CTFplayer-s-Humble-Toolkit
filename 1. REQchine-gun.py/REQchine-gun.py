# Note : Use python3.12

import argparse
import requests
import sys
import threading
import time


HALT_EVENT = threading.Event()
PLACEHOLDER_TEXT = "^REQchine^"
PLACEHOLDER_TEXT_BINARY = b"^REQchine^"
RESPONSE_LIST = {}
VERSION = "1.0"

def parse_arguments():
    parser = argparse.ArgumentParser(description="Rapidly fires customized HTTP requests at the pointed target!")
    parser.add_argument('-r', '--request', type=str, required=True, help='File containing the HTTP request packet')
    parser.add_argument('-w', '--wordlist', type=str, help='A Wordlist containing the words to be used as replacements in the HTTP requests')
    parser.add_argument('-p', '--pathlist', type=str, help='Future Work: A Pathlist containing the paths of various wordlists to be used. The first wordlist would be used for the first target, the second wordlist for the second target and so on.')
    parser.add_argument('-v', '--verbose', action='store_true', help='For Verbose Output')
    

    return parser

def check_arguments(args, parser):

    if args.wordlist is None and args.pathlist is None:
        parser.error("No wordlist or pathlist provided. You must supply a --wordlist or a --pathlist for the tool to work correctly.")
    
    if args.wordlist and args.pathlist:
        parser.error("Both --wordlist and --pathlist have been provided. You must supply only one of the two arguments for the tool to work correctly.")


def print_banner():
    width = 100
    print(f"\n{'+ - + - + - + - + - + - + - + - + - + - + - + - + - + - +'.center(width)}")
    print("      _________________")
    print("     /__   ________   /")
    print("       /  /       /  /")
    print("      /  /_______/  / //=====  //=======")
    print("     /   __________/ //       //      //       //")
    print("    /    \\          //       //      //       //")
    print("   /  /\\  \\        //=====  //      //       //      o")
    print("  /  /  \\  \\      //       // \\\\   // //=== //===\\\\ ///^===\\\\ //==\\\\   //==\\\\ //   ///^===\\\\    //==\\\\ //   //")
    print(" /  /    \\  \\_   //       //   \\\\ ////     //   // // //   ////===//==//   ////   // //   //   //   ////   //")
    print("/__/      \\___/ //====== //======// \\\\=== //   // // //   // \\\\====   \\\\==// \\\\==// //   // o //===// \\\\==//")
    print("                                 \\\\                                      //                  //          //")
    print("                                  \\\\                                \\\\==//                  //      \\\\==//")
    version_str = f"Version {VERSION}"
    centered_v_str = version_str.center(width)
    print(f"\n\n{centered_v_str}\n")
    print(f"{'+ - + - + - + - + - + - + - + - + - + - + - + - + - + - +'.center(width)}\n")



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
            print(f"[ERROR] : The file '{args.pathlist}' was not found.")
            exit(1)
        except Exception as e:
            print(f"[ERROR] : {e}")
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
        print(f"[ERROR] : The file '{path}' was not found.")
        exit(1)
    except Exception as e:
        print(f"[ERROR] : {e}")
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

def calculate_res_length(response):
    status_line_length = 12 + len(str(response.status_code)) + len(response.reason)
    headers_length = sum(len(k) + len(v) + 4 for k, v in response.headers.items())
    body_length = len(response.content)

    return status_line_length + headers_length + 2 + body_length

def collect_response_and_print(response, payloads):
    res_list_length = len(RESPONSE_LIST)
    if res_list_length == 0:
        print("----------------------------------------------------------------------")
        print(f"REQ No.\t\tPayload(s)\t\tStatus\t\tRES Length")
        print("----------------------------------------------------------------------")
    res_length = calculate_res_length(response)
    RESPONSE_LIST[res_list_length+1] = (response, payloads, res_length)
    print(f" {res_list_length+1}\t\t{', '.join(payloads)}\t\t\t{response.status_code}\t\t{res_length}")

def inspect_response(req_num):
    print(f"\n--- INSPECTION VIEW FOR REQ NO. {req_num} ---------------")
    res_tuple = RESPONSE_LIST[req_num]
    print(f"\nPAYLOAD(S)\t: {", ".join(res_tuple[1])}")
    print(f"RES LENGTH\t: {res_tuple[2]}")
    print(f"STATUS LINE\t: {res_tuple[0].status_code} {res_tuple[0].reason}")
    time.sleep(0.3)
    print("\n**** HEADERS ****\n")
    print("\n".join([f"{k}\t: {v}" for k,v in res_tuple[0].headers.items()]))
    time.sleep(0.3)
    print(f"\nThe length of the Response Body is {len(res_tuple[0].content)}")
    choice = input("Enter 'y' if you want to print the Body : ")
    if choice == 'y':
        print("\n**** BODY ****\n")
        print(res_tuple[0].text)
        time.sleep(0.7)
    print(f"\n---END OF INSPECTION VIEW FOR REQ NO. {req_num} ----------\n")
    time.sleep(0.5)
    
def display_response_stats(called_from):
    print("\n----- RESPONSE STATS -------------------")
    time.sleep(0.5)
    print(f"REQs Fired\t\t\t   : {len(RESPONSE_LIST)}") 
    status_code_counts = {}
    length_counts = {}
    for req_id, res_tuple in RESPONSE_LIST.items():
        
        if res_tuple[0].status_code in status_code_counts:
            status_code_counts[res_tuple[0].status_code] += 1
        else:
            status_code_counts[res_tuple[0].status_code] = 1
        
        if res_tuple[2] in length_counts:
            length_counts[res_tuple[2]] += 1
        else:
            length_counts[res_tuple[2]] = 1

    print(f"Status codes of received responses : {"\t".join([ f"{k} ({v} responses)" for k, v in status_code_counts.items()])}")
    print(f"Lengths of received responses\t   : {"\t".join([ f"{k} ({v} responses)" for k, v in length_counts.items()])}")
    time.sleep(0.75)
    while True:
        print("\nWhat do you want to do next?")
        print("[1] Inspect a single response\t[2] Inspect responses with a specific status code")
        if called_from == "ERF":
            print("[3] Inspect responses with a specific RES length\t[4] Exit the tool")
        else:
            print("[3] Inspect responses with a specific RES length\t[4] Go back to the Halt Menu")
        print("[5] Display the Stats again")
        selected_option = input("\nSelect an option : ")

        if selected_option == "1":
            req_num = int(input("Enter the REQ No. of the response to be inspected: "))
            if req_num in range(1, len(RESPONSE_LIST)+1):
                inspect_response(req_num)
                print("\n[INFO] : Back to Response Stats Menu\n")
            else:
                print("\n[ERROR] : Entered an Incorrect REQ No.\n")
                time.sleep(0.75)

        elif selected_option == "2":
            s_code = int(input("Enter the status code to be used as filter : "))
            if s_code in status_code_counts:
                s_code_count = status_code_counts[s_code]
                i = 0
                for r_id, r_tuple in RESPONSE_LIST.items():
                    if r_tuple[0].status_code == s_code:
                        inspect_response(r_id)
                        i += 1
                        print(f"[INFO] : {i}/{s_code_count} REQ(s) with Status Code {s_code} inspected.")
                        time.sleep(0.6)

                print("\n[INFO] : Back to Response Stats Menu\n")
            else:
                print(f"\n[ERROR] None of the responses have a status code of {s_code}\n")
                time.sleep(0.75)
            
        elif selected_option == "3":
            res_len = int(input("Enter the RES Length to be used as filter : "))
            if res_len in length_counts:
                res_len_count = length_counts[res_len]
                j = 0
                for r_id, r_tuple in RESPONSE_LIST.items():
                    if r_tuple[2] == res_len:
                        inspect_response(r_id)
                        j += 1
                        print(f"[INFO] : {j}/{res_len_count} REQ(s) with Length {res_len} inspected.")
                        time.sleep(0.6)

                print("\n[INFO] : Back to Response Stats Menu\n")
            else:
                print(f"\n[ERROR] None of the responses have a RES Length of {res_len}\n")
                time.sleep(0.75)
        
        elif selected_option == "4":
            if called_from == "ERF":
                confirmation = input("Are you sure you want to exit [y/n] : ")
                if confirmation == 'y':
                    print("\n[INFO] : Exiting REQchine-gun.py. Bye!\n")
                    time.sleep(0.5)
                    exit(0)
                else:
                    print("\n[INFO] : Exit cancelled.\n")
                    time.sleep(0.75)
            else:
                print("\n[INFO] : Going back to the Halt Menu\n")
                time.sleep(0.5)
                return
        
        elif selected_option == "5":
            print("\n----- RESPONSE STATS -------------------")
            time.sleep(0.5)
            print(f"REQs Fired : {len(RESPONSE_LIST)}") 
            print(f"Status codes of received responses: ")
            print("\t".join([ f"{k} ({v} responses)" for k, v in status_code_counts.items()]))
            print(f"Lengths of received responses: ")
            print("\t".join([ f"{k} ({v} responses)" for k, v in length_counts.items()]))
            time.sleep(0.75)
        
        else:
            print("\n[INFO] : Please enter a valid option!\n")
            time.sleep(0.75)


def end_req_firing():
    if not HALT_EVENT.is_set():
        print("\n[INFO] : Completed REQs firing")
        time.sleep(0.5)
        print("[INFO] : Press <ENTER> Key to display Response Stats")
        while not HALT_EVENT.is_set():
            time.sleep(0.3)
    else:
        print("\n[INFO] : Ended REQs firing")
        time.sleep(0.5)
    
    print("[INFO] : Displaying Response Stats")
    time.sleep(0.5)
    display_response_stats("ERF")
    

def halt_req_firing():
    print("\n[INFO] : Halted REQs Firing!\n")
    time.sleep(0.5)
    while True:
        print("----- HALT MENU -------------------")
        print("[c] to Continue REQs Firing  | [d] to Display stats")
        print("[e] to End REQs Firing       | [x] to Exit the tool")
        key = input("\nSelect an option : ")
        if key == 'c':
            print("\n[INFO] : Continuing REQs Firing.")
            time.sleep(0.5)
            break
        elif key == 'd':
            display_response_stats("HRF")
        elif key == 'e':
            end_req_firing()
        elif key == 'x':
            confirmation = input("Are you sure you want to exit [y/n] : ")
            if confirmation == 'y':
                print("\n[INFO] : Exiting REQchine-gun.py. Bye!")
                time.sleep(0.5)
                exit(0)
            else:
                print("\n[INFO] : Exit cancelled.\n")
                time.sleep(0.75)
        else:
            print("\n[INFO] : Please enter a valid option!\n")
            time.sleep(0.75)


def look_for_firing_halt_signal():
    sys.stdin.read(1)
    HALT_EVENT.set()


def set_firing_halt_monitoring_thread():
    halt_monitor_thread = threading.Thread(target=look_for_firing_halt_signal)
    halt_monitor_thread.daemon = True
    print("[INFO] : To halt REQs firing at any point in time, press the <ENTER> key.\n")
    time.sleep(0.25)
    if len(RESPONSE_LIST) > 0:
        print("----------------------------------------------------------------------")
        print(f"REQ No.\t\tPayload(s)\t\tStatus\t\tRES Length")
        print("----------------------------------------------------------------------")
    halt_monitor_thread.start()

def build_and_send_packet(req_line, headers, req_body):
    if HALT_EVENT.is_set():
        halt_req_firing()
        HALT_EVENT.clear()
        set_firing_halt_monitoring_thread()
    URL = "http://" + headers["Host"] + req_line["target"]
    host_header_val = headers["Host"]
    del headers["Host"]
    try:
        if req_line["method"] == "GET":
            response = requests.get(URL, headers=headers)
            headers["Host"] = host_header_val
            return response
            
        
        elif req_line["method"] == "POST":
            response = requests.post(URL, headers=headers, data=req_body)
            headers["Host"] = host_header_val
            return response
            
        else:
            print("\n[ERROR] The tool only supports GET/POST requests, as of now.")
            time.sleep(0.75)
            print("\n[INFO] : Exiting REQchine-gun.py...")
            print("[INFO] : Press <ENTER> Key to exit")
            exit(1)
    
    except requests.exceptions.ConnectionError as e:
        print("\n[ERROR] : Connection Error\n")
        print(e)
        time.sleep(0.75)
        print("\n[INFO] : Exiting REQchine-gun.py...")
        print("[INFO] : Press <ENTER> Key to exit")
        exit(1)
    except requests.exceptions.RequestException as e:
        print(e)
        time.sleep(0.75)
        print("\n[INFO] : Exiting REQchine-gun.py...")
        print("[INFO] : Press <ENTER> Key to exit")
        exit(1)


def handle_single_replacement_in_req_line(req_line_obj, headers, req_body, wl_file):
    try:
        with open(wl_file) as wordlist_file:
            
            original_target = req_line_obj["target"]
            set_firing_halt_monitoring_thread()
            for word in wordlist_file:
                replacement = word.strip()
                req_line_obj["target"] = req_line_obj["target"].replace(PLACEHOLDER_TEXT, replacement, 1)
                
                collect_response_and_print(build_and_send_packet(req_line_obj, headers, req_body), (replacement,))
                
                req_line_obj["target"] = original_target
            
            end_req_firing()
            

    except FileNotFoundError:
        print(f"[ERROR] : The file '{wl_file}' was not found.")
        exit(1)
    except Exception as e:
        print(f"[ERROR] : {e}")
        exit(1)


def handle_single_replacement_in_header(req_line_obj, header_obj, req_body, header, value, wl_file):
    try:
        with open(wl_file) as wordlist_file:
            set_firing_halt_monitoring_thread()
            for word in wordlist_file:
                replacement = word.strip()
                header_obj[header] = header_obj[header].replace(PLACEHOLDER_TEXT, replacement, 1)
                collect_response_and_print(build_and_send_packet(req_line_obj, header_obj, req_body), (replacement,))
                header_obj[header] = value
            
            end_req_firing()

    except FileNotFoundError:
        print(f"[ERROR] : The file '{wl_file}' was not found.")
        exit(1)
    except Exception as e:
        print(f"[ERROR] : {e}")
        exit(1)


def handle_single_replacement_in_req_body(req_line_obj, header_obj, req_body, wl_file):
    try:
        with open(wl_file) as wordlist_file:
            
            set_firing_halt_monitoring_thread()
            for word in wordlist_file:
                replacement = word.strip().encode()
                modified_req_body = req_body.replace(PLACEHOLDER_TEXT_BINARY, replacement, 1)
                header_obj["Content-Length"] = str(len(modified_req_body))
                
                collect_response_and_print(build_and_send_packet(req_line_obj, header_obj, modified_req_body), (replacement.decode('utf-8'),))
            
            end_req_firing()
            
    except FileNotFoundError:
        print(f"[ERROR] : The file '{wl_file}' was not found.")
        exit(1)
    except Exception as e:
        print(f"[ERROR] : {e}")
        exit(1)


def make_replacements_and_fire_the_gun(req_filepath, r_count, r_filepaths, req_line_obj, header_obj, req_body):
    
    print("[INFO] : Initiated REQs Firing!")
    time.sleep(0.5)
    
    if r_count == 1:
        
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
            print(f"[ERROR] : No replacement target (^REQchine^) was found in the provided request file '{req_filepath}'. Check your file!")
            exit(1)
        else:
            if PLACEHOLDER_TEXT_BINARY in req_body:
                handle_single_replacement_in_req_body(req_line_obj, header_obj, req_body, r_filepaths[0])

            else:
                print(f"[ERROR] : No replacement target (^REQchine^) was found in the provided request file '{req_filepath}'. Check your file!")
                exit(1)

    else:
        print("Future work.")

def main():
    
    # Argument parsing, Banner printing and dealing with verbose O/p

    parser = parse_arguments()
    args = parser.parse_args()
    check_arguments(args, parser)
    print_banner()
    replacements_count, replacements_filepaths = get_replacements_count_and_filepaths(args)
    #print(replacements_count)
    #print(replacements_filepaths)
    print_verbose_output(args)
    

    # Extraction of the packet's sections

    packet_req_line, packet_headers, packet_body = extract_packet_sections(args.request)

    # Parsing of the packet's sections
    
    req_line_obj = parse_request_line(packet_req_line)
    header_obj = parse_headers(packet_headers)
    req_body = packet_body if packet_body else None

    # The core functionality

    make_replacements_and_fire_the_gun(args.request, replacements_count, replacements_filepaths, req_line_obj, header_obj, req_body)
    

if __name__ == "__main__":
    main()