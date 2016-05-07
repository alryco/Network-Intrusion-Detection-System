#include "traffic_analyzer.h"
#include "network_protocols.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <queue>
#include <string.h>
#include <unistd.h>
#include <chrono>	// for timing
#include <thread>	// threading library
#include <mutex>	// thread mutex

#include <sys/socket.h>	// socket library
#include <netinet/in.h> // socket structs (i.e. sockaddr_in, etc.)
#include <arpa/inet.h>	// inet_aton() etc.

#include <pcap.h>	// pcap library



using namespace std;

#define MAXBUFLEN 512
#define DESMAN_PORT 11353


mutex g_mtx;			// so we can synchronize access to TrafficAnalyzer instance between threads
string g_logfile;

bool g_liveMode;		// TRUE if we're reading packets from a live interface

queue<string> g_reports;
long long int g_maxts_usecs = 0; // max timestamp value for this timeslice
double g_timeslice = 1.0;			 // our timeslice length in seconds (default = 1.0)


/** Appends MSG to m_logfile and to console **/
void LogMessage(const string& msg)
{
	fstream fs; 

	fs.open(g_logfile, fstream::out | fstream::app);
	fs << msg << endl;
	fs.close();

	cout << msg << endl;
}


/** Prints usage instructions **/
void PrintUsgInstr()
{
	cout << "\nWatchdog Usage Instructions:\n\n";
	cout << "> watchdog [-r filename] [-i interface] [-w filename] [-c desmanIP] [-t timeslice]\n";
	cout << "where\n";
	cout << "-r, --read\t\tRead the specified file\n";
	cout << "-i, --interface\t\tListen on the specified interface\n";
	cout << "-w, --write\t\tWrite the output in the specified log file\n";
	cout << "-c, --connect\t\tConnect to the specified IP address for the desman\n";
	cout << "OPTIONAL:\n";
	cout << "-t, --timeslice\t\tNumber of seconds to monitor traffic before sending report to desman (default = 1.0)\n";
}


/** Parses cmd line arguments and saves options into fn args.
	Returns TRUE if all opts are valid 
	Returns FALSE if anything goes wrong or if any opts are invalid **/
bool ParseCmdLineArgs(int argc, char** argv, string& pcapfile, string& interface, 
							string& logfile, string& desmanIP, double& timeslice)
{
	
	pcapfile = "";
	interface = "";
	logfile = "";
	desmanIP = "";
	timeslice = 1.0;

	int c;

	while ((c = getopt(argc, argv, "r:i:w:c:t:")) != -1)
	{
		switch (c)
		{
			case 'r':
				pcapfile = optarg;
				g_liveMode = false;
				break;
			case 'i':
				interface = optarg;
				g_liveMode = true;
				break;
			case 'w':
				logfile = optarg;
				break;
			case 'c':
				desmanIP = optarg;
				break;
			case 't':
				istringstream(string(optarg)) >> timeslice;
				break;
			default:
				return false;
		}
	}

	// verify user options are valid
	if (desmanIP == "")
	{
		cout << "Error: must provide desman IP\n";
		return false;
	}

	if (logfile == "")
	{
		cout << "Error: must provide logfile name\n";
		return false;
	}

	if (interface == "" && pcapfile == "")
	{
		cout << "Error: must provide live interface name or pcapfile\n";
		return false;
	}

	if (interface != "" && pcapfile != "")
	{
		cout << "Error: Please provide only one of either live interface name or pcapfile (not both)\n";
		return false;
	}

	if (timeslice < 0.1)
	{
		cout << "Error: timeslice must be at least 0.1 seconds\n";
		return false;
	}

	return true;
}


/** Establishes a TCP connection to the desman returning assigned WD ID upon success. 
	Returns -1 if any errors occured **/
int ConnectToDesman(int& sockfd, sockaddr_in* pSA)
{
	/** Create the socket **/
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		cout << "Error creating socket\n";
		return -1;
	}

	/** Connect to desman **/
	if (connect(sockfd, (sockaddr *)pSA, sizeof(*pSA)) == -1)
	{
		cout << "Error connecting to server\n";
		return -1;
	}

	cout << "Connected to desman\n";

	/** Receive "UID <id>" msg from desman **/
	char buf[MAXBUFLEN] = {0};
	if (recv(sockfd, buf, MAXBUFLEN, 0) == -1)
	{
		cout << "Error receiving ID from desman\n";
		return -1;
	}
	string msg(buf);

	/** parse msg to get ID as an integer and return **/
	msg.erase(0, 4); // strip "UID " from msg so only the actual id value remains
	int id;
	istringstream(msg) >> id; // convert id to integer

	return id;
}


/** Waits to receive 'start' message from desman.
	Returns TRUE when start msg successfully received.
	Returns FALSE if any errors occured **/
bool StandbyToStart(int sockfd)
{
	char buf[MAXBUFLEN] = {0};

	if (recv(sockfd, buf, MAXBUFLEN, 0) == -1)
	{
		return false;
	}

	if (string(buf) != "start")
	{
		return false;
	}

	return true;
}


void GetPacket(u_char* args, const pcap_pkthdr* header, const u_char* packet)
{
	TrafficAnalyzer* pTrafficAnalyzer = (TrafficAnalyzer*)args; // ptr to our TrafficAnalyzer instance

	// If we're reading from a pcapfile, need to use timestamps to monitor time
	if (!g_liveMode)
	{
		time_t secs = header->ts.tv_sec;
		long int usecOffset = header->ts.tv_usec;
		long long int ts_usecs = (secs * 1000000) + usecOffset;

		if (ts_usecs > g_maxts_usecs)
		{
			
			if (g_maxts_usecs > 0) // don't want to generate report if this is the first packet
			{			
				// If all packets for this timeslice have been added, generate report and add it to the queue
				g_mtx.lock();
				string report = pTrafficAnalyzer->GenerateReport();	
				g_reports.push(report);
				g_mtx.unlock();
			}
			g_maxts_usecs = ts_usecs + (long long int)(g_timeslice * 1000000.0);
		}
	}

	PacketInfo pktInfo; // We'll store all data we need about the packet in here

	const sniff_ip* ip;		// the IP header
	const sniff_tcp* tcp;  	// the TCP header
	u_int size_ip;			// size of ip header

	// Compute IP header offset
	ip = (sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20)
	{
		// invalid ip header length
		return;
	}

	// Determine packet size
	pktInfo.size = ntohs(ip->ip_len);

	// Determine source and destination IP addresses
	pktInfo.src_ip = inet_ntoa(ip->ip_src);
	pktInfo.dst_ip = inet_ntoa(ip->ip_dst);

	// Determine protocol (We only care about TCP/UDP)
	switch(ip->ip_p)
	{
		case IPPROTO_TCP:
			pktInfo.protocol = "TCP";
			break;
		case IPPROTO_UDP:
			pktInfo.protocol = "UDP";
			break;
		case IPPROTO_ICMP:
			pktInfo.protocol = "ICMP";
			break;
		case IPPROTO_IP:
			pktInfo.protocol = "IP";
			break;
		default:
			pktInfo.protocol = "unknown";
			return;
	}

	if (pktInfo.protocol == "TCP" || pktInfo.protocol == "UDP")
	{
		// Compute TCP header offset (can use this for UDP also since we just need src/dst ports)
		tcp = (sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);

		// Determine source and destination ports
		pktInfo.src_port = ntohs(tcp->th_sport);
		pktInfo.dst_port = ntohs(tcp->th_dport);
	}
	else
	{
		pktInfo.src_port = 0;
		pktInfo.dst_port = 0;
	}


	// Add packet to traffic analyzer for processing
	g_mtx.lock();
	pTrafficAnalyzer->AddPacket(pktInfo);
	g_mtx.unlock();
}

/** calls pcap_loop(). This code will be executed by child thread **/
void MonitorTraffic(pcap_t* pHandle, TrafficAnalyzer* pTrafficAnalyzer)
{
	pcap_loop(pHandle, -1, GetPacket, (u_char*)pTrafficAnalyzer); // loop through packets
}


int main(int argc, char** argv)
{

	/** Parse input args **/   // TODO
	string desmanIP;
	string logfile;
	string interface;
	string pcapfile;
	double timeslice;

	if (!ParseCmdLineArgs(argc, argv, pcapfile, interface, logfile, desmanIP, timeslice))
	{
		// if any invalid arguments, print usage instructions and exit
		PrintUsgInstr();
		return 0;
	}

	// save interface/timeslice value as global variables
	g_logfile = logfile;
	g_timeslice = timeslice;

	// Clear out our logfile (so any old data is overwritten)
	fstream fs; 
	fs.open(logfile, fstream::out);
	fs.close();


	/** Initialize our pcap session **/

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pHandle;

	if (g_liveMode) // If we're reading from a live interface...
	{

		pHandle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
		if (pHandle == NULL)
		{
			cout << "Couldn't open device " << errbuf << endl;
			return 0;
		}
	}
	else // If we're reading from a pcap file...
	{
		pHandle = pcap_open_offline(pcapfile.c_str(), errbuf);
		if (pHandle == NULL)
		{
			cout << "Couldn't open pcap file " << errbuf << endl;
			return 0;
		}
	}



	/** Establish connection to desman and receive ID **/

	int sockfd;
	sockaddr_in sockaddr;

	// Setup our sockaddr_in struct
	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(DESMAN_PORT);
	if (inet_aton(desmanIP.c_str(), &sockaddr.sin_addr) == 0)
	{
		cout << "Error setting IP address\n";
		return 0;
	}

	// Log "Connecting to desman..." msg
	LogMessage("Connecting to desman at " + desmanIP + "...");

	int id = 0;
	if ((id = ConnectToDesman(sockfd, &sockaddr)) == -1)
	{
		cout << "Unable to establish connection to Desman\n";
		return 0;
	}

	// Log "Received <UID>" msg
	ostringstream ossRecvdIdMsg;
	ossRecvdIdMsg << "Received " << id;
	LogMessage(ossRecvdIdMsg.str());



	/** START **/

	// wait to receive start signal from desman
	if (!StandbyToStart(sockfd))
	{
		cout << "Error receiving start signal from desman\n";
		return 0;
	}

	LogMessage("Received start...");


	TrafficAnalyzer trafficAnalyzer(logfile);	// Create our TrafficAnalyzer instance

	// Create child thread to loop through packets, storing packet data in trafficAnalyzer
	thread trafficMonitor_th(MonitorTraffic, pHandle, &trafficAnalyzer);

	
	if (g_liveMode) /** MAIN APPLICATION LOOP - LIVE INTERFACE **/
	{
		// Main thread generates reports every TIMESLICE (wallclock) and sends them to desman
		do
		{
			// sleep for TIMESLICE secs...
			this_thread::sleep_for(chrono::milliseconds( (int)(g_timeslice * 1000) )); 

			// process data and generate report
			g_mtx.lock();
			string report = trafficAnalyzer.GenerateReport();
			g_mtx.unlock();

			// send report to desman
			if (send(sockfd, report.c_str(), report.length(), 0) == -1)	
			{
				cout << "Error sending report to desman\n";
				return 0;
			}
		}
		while (1); // Run until user terminates (via ctrl+C)
	}
	else /** MAIN APPLICATION LOOP - PCAP FILE **/
	{
		do
		{
			// sleep for TIMESLICE secs...
			this_thread::sleep_for(chrono::milliseconds( (int)(g_timeslice * 1000) ));

			// grab next report from queue (processing done ahead of time)
			g_mtx.lock();
			string report = g_reports.front();
			g_reports.pop();
			g_mtx.unlock();

			// send report to desman
			if (send(sockfd, report.c_str(), report.length(), 0) == -1)	
			{
				cout << "Error sending report to desman\n";
				return 0;
			}
		}
		while (!g_reports.empty()); // Once all reports are sent we can terminate
	}
	


	trafficMonitor_th.join();
	pcap_close(pHandle);
	return 0;
}

