#include "connection_manager.h"

#include <iostream>
#include <sstream>
#include <fstream>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>		// socket library
#include <netinet/in.h>		// socket structs (i.e. sockaddr_in, etc.)
#include <arpa/inet.h>		// inet_aton() etc.
#include <ifaddrs.h>		// getifaddrs()


#define MAXWATCHDOGS 10
#define MAXBUFLEN 512
#define DESMAN_PORT 11353


/** @param msg The message to be written to m_logfile and console. 
	*/
void ConnectionManager::LogMessage(const string& msg) const
{
	fstream fs; 
	fs.open(m_logfile, fstream::out | fstream::app);
	fs << msg << endl;
	fs.close();

	cout << msg << endl;
}

/** Called internally whenever the connection to a watchdog is lost. 
	Decrements m_numWatchdogs and removes the entry from m_idMap.
	@param fd the socket file descriptor of the watchdog to remove
	*/
void ConnectionManager::RemoveWatchdog(int fd)
{
	m_numWatchdogs--;
	m_idMap.erase(fd);
	close(fd);
}


/** Called internally within InitializeSocket() method to determine the local ip of the host machine 
	desman is running on. Uses getifaddrs() to determine the first valid ipv4 address (excluding localhost) 
	and returns it via the ip_addr param. 

	@param[out] ip_addr String containing the host's local ip address in dot-quad notation

	@return TRUE if local ip was found successfully, otherwise returns FALSE if it couldn't be found or any errors occured
	*/
bool ConnectionManager::FindIPAddress(string& ip_addr) const
{
	struct ifaddrs* ifa;
	string localhost = "127.0.0.1";

	if (getifaddrs(&ifa) == -1)
	{
		return false;
	}

	// loop through linked list of addresses and return first external ipv4 address
	while (ifa)
	{
		if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) // only care about ipv4 addresses			
		{
			// Return first valid ipv4 address (excluding localhost)
			struct sockaddr_in * sa = (struct sockaddr_in *)ifa->ifa_addr;
			char* addr_buf = inet_ntoa(sa->sin_addr);
			ip_addr = string(addr_buf);
			if (ip_addr != localhost)
			{
				return true;
			}
		}

		ifa = ifa->ifa_next;
	}

	// if we couldn't find one return false;
	return false;
	
}


/** Called internally by EstablishWDConnections() method. First determines IP address to use (via FindIPAddress() method),
	then acquires a TCP socket from the OS and binds to it. 

	@return socket file descriptor of socket that we successfully bound to, or -1 if any errors occured.
	*/
int ConnectionManager::InitializeSocket() const
{
	int fd;
	sockaddr_in sa;

	// Determine our IP address
	string ip;
	if (!FindIPAddress(ip))
	{
		cout << "Error finding desman's ip address\n"; 
	}

	// Setup our sockaddr_in struct
	memset((char *)&sa, 0, sizeof(sa)); // clear out our sockaddr_in struct
	sa.sin_family = AF_INET; // ipv4
	sa.sin_port = htons(DESMAN_PORT);
	if (inet_aton(ip.c_str(), &sa.sin_addr) == 0)
	{
		cout << "Error setting desman IP address\n";
		return -1;
	}

	cout << "Desman started on " << ip << " at port " << DESMAN_PORT << "...\n";

	// create our socket
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		cout << "Error creating socket\n"; 
		return -1;
	}

	// Bind to the socket
	if (bind(fd, (sockaddr *)&sa, sizeof(sa)) == -1)
	{
		cout << "Error binding socket\n";
		return -1;
	}

	return fd;
}


/** Initializes ConnectionManager instance with number of watchdogs to connect to and name of file to log to. 
	
	@param numWDs Number of watchdogs that we'll connect to when EstablishWDConnections() is called 
	@param logfile Name of the logfile that relevent info will be logged to 
	*/
ConnectionManager::ConnectionManager(int numWDs, string logfile)
{
	m_numWatchdogs = numWDs;
	m_logfile = logfile;
}


/**	First uses InitializeSocket() helper function to acquire and bind to a TCP socket using the host's local IP address.
	Begins listening on the socket for incoming watchdog connections. Once a watchdog connects, a watchdog ID is assigned
	and mapped to the watchdogs socket file descriptor for future communications. The ID is then sent back to that watchdog.
	The function returns once m_numWatchdogs watchdogs are successfully connected (or an error occurs).

	@return TRUE if all watchdogs successfully connected, or FALSE if an error occured.
	*/
bool ConnectionManager::EstablishWDConnections()
{
	int listener; // our (desman's) sockfd

	if ((listener = InitializeSocket()) == -1)
	{
		return false;
	}

	// start listening for incoming WD connections 
	if (listen(listener, MAXWATCHDOGS) == -1)
	{
		cout << "Error listening for connections\n";
		return false;
	}

	LogMessage("Listening on port 11353...");

	// Wait to receive connection from each watchdog and assign ID
	for (int i = 0; i < m_numWatchdogs; i++)
	{
		int watchdog;			// sockfd for this watchdog
		sockaddr_in wdAddr;	// watchdog's address info will be stored in here
		int id = i + 1;			// id that we'll assign to this watchdog

		// accept incoming watchdog connection
		socklen_t addrlen = sizeof(wdAddr);
		if ((watchdog = accept(listener, (sockaddr *)&wdAddr, &addrlen)) == -1)
		{
			cout << "Error accepting connection to watchdog " << id << endl;
			return false;
		}

		// log "incoming watchdog connection..." msg
		string ipStr = inet_ntoa(wdAddr.sin_addr);
		LogMessage("Incoming watchdog connection from IP " + ipStr);
		
		// assign watchdog an ID
		ostringstream ossIdMsg;
		ossIdMsg << "UID " << id;
		if (send(watchdog, ossIdMsg.str().c_str(), ossIdMsg.str().length(), 0) == -1)
		{
			cout << "Error assigning watchdog id" << endl;
			return false;
		}

		// log "Assigned UID to watchdog..." msg
		ostringstream oss;
		oss << "Assigned " << id << " to watchdog at IP " << ipStr;
		LogMessage(oss.str());

		
		m_idMap[watchdog] = id;
	}

	LogMessage("All watchdogs connected...");
	return true;
}


/** Should be called after EstablishWDConnections() returns TRUE. Simply iterates through m_idMap sending 
	a message containing "start" to each watchdog.

	@return TRUE if start signal was successfully sent to each WD, or FALSE if any errors occured
	*/
bool ConnectionManager::SendStartSignal() const
{
	LogMessage("Issuing start monitoring...");

	string startMsg = "start";

	for (auto it = m_idMap.begin(); it != m_idMap.end(); it++)
	{
		if (send(it->first, startMsg.c_str(), startMsg.length(), 0) == -1)
		{
			cout << "Error sending start signal to WD " << it->first << endl;
			return false;
		}
	}

	return true;
}

/** Should be called in a loop immediately after SendStartSignal() returns TRUE. Uses the select() function
	to monitor all incoming messages from watchdogs. Once a report is received from a watchdog, it is logged 
	via the LogMessage() method. If connection to a watchdog is lost, RemoveWatchdog() is called causing that
	watchdog to stop being tracked. The user is notified via console in the event that this occurs. If all
	watchdogs have disconnected and there are no more reports to receive, this method will return FALSE indicating
	to the caller that the watchdogs have finished monitoring and the desman can terminate as well.

	Once a report is received from each connected watchdog, the reports are returned to the caller in a vector 
	via the reports param.

	@param[out] reports A vector containing the watchdog reports received
	
	@param return TRUE if at least one watchdog is still connected. FALSE if all watchdogs have disconnected.
	*/
bool ConnectionManager::ReceiveWDReports(vector<string>& reports)
{
	reports.clear();

	int reportsToRecv = m_numWatchdogs;

	int fdMax = 0;
	fd_set watchdogs;
	FD_ZERO(&watchdogs); // make sure our fd_set is empty

	// add all our watchdog FDs to the 'watchdogs' fdset and determine fdMax
	for (auto it = m_idMap.begin(); it != m_idMap.end(); it++)
	{
		FD_SET(it->first, &watchdogs);
		if (it->first > fdMax) fdMax = it->first;
	}

	// loop until we've received reports from all of our watchdogs
	while (reportsToRecv > 0)
	{
		
		fd_set readFds = watchdogs;

		if (select(fdMax+1, &readFds, NULL, NULL, NULL) == -1) // Get fds that are ready to be read from
		{
			cout << "Error calling select()\n";
		}

		for (int i = 0; i <= fdMax; i++)
		{
			if (FD_ISSET(i, &watchdogs))
			{
				char buf[MAXBUFLEN] = {0};
				int bytes;
				if ((bytes = recv(i, buf, sizeof(buf), 0)) <= 0)
				{
					// if we lost connection or an error occured, stop tracking this watchdog
					cout << "Lost connection with watchdog " << m_idMap[i] << endl;
					RemoveWatchdog(i);
					if (m_numWatchdogs == 0)
					{
						return false;
					}
				}
				else // Received report successfully
				{
					string report(buf);
					reports.push_back(report); // add report to list

					// Insert ID into report so we can log it
					ostringstream oss;
					oss << " " << m_idMap[i];
					string idStr = oss.str();
					int pos = report.find("report") + 6;
					report.insert(pos, idStr);

					// Log "Received report..." message
					LogMessage("Received " + report);
				}
				reportsToRecv--;
			}
		}
	}

	

	return true;
}