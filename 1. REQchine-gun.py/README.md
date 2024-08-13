# REQchine-gun.py

```
      _________________
     /__   ________   /
       /  /       /  /
      /  /_______/  / //=====  //=======
     /   __________/ //       //      //       //
    /    \          //       //      //       //
   /  /\  \        //=====  //      //       //      o
  /  /  \  \      //       // \\   // //=== //===\\ ///^===\\ //==\\   //==\\ //   ///^===\\    //==\\ //   //
 /  /    \  \_   //       //   \\ ////     //   // // //   ////===//==//   ////   // //   //   //   ////   //
/__/      \___/ //====== //======// \\=== //   // // //   // \\====   \\==// \\==// //   // o //===// \\==//
                                 \\                                      //                  //          //
                                  \\                                \\==//                  //      \\==//


                                            Version 1.0                                             

```

***REQchine-gun.py*** is a tool to send customized `HTTP/1.1` requests to a specifc target. 

## The tool's working

- The tool works by replacing placeholder(s) *(specified by the string `^REQchine^`)* in a `HTTP/1.1` request *(provided as a file)*. 

- The replacements are performed with the words from a wordlist or multiple wordlists *(specified by a pathlist)* supplied by the user.

- The resulting customized requests are sent to the target determined from the request's `Host` header. 

- The tool provides many intuitive functionalities that help the user inspect the responses returned by the target for the various customized HTTP requests that were sent to it.

- Supports GET and POST requests. In the case of POST requests, there is support for various content types such as `application/x-www-form-urlencoded`, `multipart/form-data`, etc.

## Use cases

**REQchine-gun.py** helps in replacing different parts of an HTTP request as determined by the user (by the utilization of the placeholder `^REQchine^`) with words from one or more wordlists.

Common targets for such replacements include values of form fields, HTTP headers and the target path specified in the request line of the request. The tool is especially useful in SSRF scenarios where you would typically have to do a very quick scan of the entire port range to determine the port on which the local HTTP server is listening on.

```bash
# Note : Use python3.12

python3 REQchine-gun.py --help
usage: REQchine-gun.py [-h] -r REQUEST [-w WORDLIST] [-p PATHLIST] [-v]

Rapidly fires customized HTTP requests at the pointed target!

options:
  -h, --help            show this help message and exit
  -r REQUEST, --request REQUEST
                        File containing the HTTP request packet
  -w WORDLIST, --wordlist WORDLIST
                        A Wordlist containing the words to be used as replacements in the HTTP requests
  -p PATHLIST, --pathlist PATHLIST
                        Future Work: A Pathlist containing the paths of various wordlists to be used. The first wordlist would be used
                        for the first target, the second wordlist for the second target and so on.
  -v, --verbose         For Verbose Output
```

## Disclaimer

This tool is only intended for educational purposes and for legitimate security testing of systems for which the tester has **written authorization** to do so from the systems' owner. 

**Do not make illegal use of this tool!**