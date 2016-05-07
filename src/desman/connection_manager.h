#ifndef CONNECTION_MANAGER_H
#define CONNECTION_MANAGER_H

#include <string>
#include <vector>
#include <map>

using namespace std;



/** @brief Used by the desman to establish and maintain all connections/communications with watchdog clients
	
	Provides an interface between the desman and watchdogs. Public methods provide ability to 
	connect (via TCP) to watchdogs, send start signal, then listen for reports sent by watchdogs so they can 
	be easily received and processed by desman.

	In the event that the connection to a watchdog is lost, the connection mananger will notify the 
	user of the loss and continue to function, receiving future reports from the other watchdogs.
	*/
class ConnectionManager
{

private:

	/** The number of watchdogs currently connected */
	int m_numWatchdogs;

	/** The name of the file to log to */ 	
	string m_logfile;		

	/** Stores a mapping of watchdog sockfd to watchdog ID */
	map<int, int> m_idMap; 	

	/** @brief Appends a message to m_logfile and console */
	void LogMessage(const string& msg) const;

	/** @brief Stops tracking a WD */
	void RemoveWatchdog(int fd);

	/** @brief Finds an ip address for the desman to use. */
	bool FindIPAddress(string& ipAddr) const;

	/** @brief Initializes TCP socket returning sockfd */
	int InitializeSocket() const;


public:

	/** @brief Constructor */ 
	ConnectionManager(int numWDs, string logfile);

	/** @brief Establishes connection to all watchdogs, returning TRUE after all WD's successfully connected */
	bool EstablishWDConnections();

	/** @brief Sends start signal to all watchdogs */
	bool SendStartSignal() const;

	/** @brief Waits to receive reports from all watchdogs returning them to caller as a vector of strings **/
	bool ReceiveWDReports(vector<string>& reports); 

};









#endif