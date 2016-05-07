# Network-Intrusion-Detection-System
A network intrusion detection system that monitors bidirectional network traffic from various locations and reports statistical anomalies to a central decision making server


## System Requirements
- OS: Linux (Ubuntu 14.04)
- Compiler: g++ (with C++11)


## Compiling Instructions
- Use 'make' to build the project. (Requires C++11 supported compiler)
- Use 'make clean' to remove object/executable files.

## Usage Instructions
- Use ./desman [args] to run the desman server and specify how many watchdogs will be connecting.
- The desman's IP address will be written to the console so the user can easily enter it as an argument when running the watchdogs.
- Use ./watchdog [args] to run each individual watchdog client. (NOTE: when running a watchdog with the [-i interface] option, the user may need to elevate their permission level (via 'sudo ./watchdog...' or 'sudo su') to gain access to the device).
- If no args (or invalid args) are provided for either, usage instructions will print to console along with an error message indicating which argument was invalid.
- If the watchdogs are monitoring packets on a live interface, they will continue to run and send reports to the desman until terminated by user (via ctrl+c), or until the desman is terminated. 
- If the watchdogs are reading packets from a .pcap file, they will run until all reports are sent and then terminate.
- Once all watchdogs have terminated, the desman will also terminate.
