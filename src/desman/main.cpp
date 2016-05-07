#include "connection_manager.h"

#include <iostream>
#include <sstream>
#include <fstream>
#include <unistd.h>

using namespace std;


string g_logfile;


/** Appends MSG to m_logfile and prints to console **/
void LogMessage(const string& msg)
{
	fstream fs;
	fs.open(g_logfile, fstream::out | fstream::app);
	fs << msg << endl;
	fs.close();

	cout << msg << endl;
}

/** Prints usage instructions to console **/
void PrintUsgInstr()
{
	cout << "\nDesman Usage Instructions:\n\n";
	cout << "> desman [-w filename] [-n number]\n";
	cout << "where\n";
	cout << "-w, --write\t\tWrite the output in the specified log file\n";
	cout << "-n, --number\t\tThe number of watchdogs in the NIDS\n";
}

/** Parses cmd line arguments and saves options into fn args.
	Returns TRUE if all opts are valid 
	Returns FALSE if anything goes wrong or if any opts are invalid **/
bool ParseCmdLineArgs(int argc, char** argv, string& logfile, int& numWatchdogs)
{
	
	numWatchdogs = 0;
	logfile = "";

	int c;

	while ((c = getopt(argc, argv, "w:n:")) != -1)
	{
		switch (c)
		{
			case 'w':
				logfile = optarg;
				break;
			case 'n':
				numWatchdogs = atoi(optarg);
				break;
			default:
				return false;
		}
	}

	// verify user options are valid
	if (numWatchdogs < 1)
	{
		cout << "Error: Number of watchdogs must be greater than 0" << endl;
		return false;
	}

	if (logfile == "")
	{
		cout << "Error: must provide logfile name" << endl;
		return false;
	}

	return true;
}


/** Extracts data from list of reports, sums it, then logs the results **/
void ProcessReports(vector<string> reports)
{
	int totalPackets=0, totalBytes=0, totalFlows=0;

	for (unsigned int i = 0; i < reports.size(); i++)
	{
		// Parse report data into vector of strings
		vector<string> reportData;
		istringstream iss(reports[i]);
		while (iss)
		{
			string tok;
			iss >> tok;
			reportData.push_back(tok);
		}

		// convert data to integers
		int packets=0, bytes=0, flows=0;
		if (reportData[0] == "alert")
		{
			istringstream(reportData[3]) >> packets;
			istringstream(reportData[4]) >> bytes;
			istringstream(reportData[5]) >> flows;
		}
		else 
		{
			istringstream(reportData[2]) >> packets;
			istringstream(reportData[3]) >> bytes;
			istringstream(reportData[4]) >> flows;
		}

		// increment totals
		totalPackets += packets;
		totalBytes += bytes;
		totalFlows += flows;
	}

	// Log data totals
	ostringstream oss;
	oss << "Total traffic " << totalPackets << " " << totalBytes << " " << totalFlows;
	LogMessage(oss.str());

}

int main(int argc, char** argv)
{	

	/** Parse cmd line arguments **/
	string logfile;
	int numWatchdogs;
	if (!ParseCmdLineArgs(argc, argv, logfile, numWatchdogs))
	{
		// if any invalid arguments, print usage instructions and exit
		PrintUsgInstr();
		return 0;
	}
	g_logfile = logfile; // save logfile as global variable

	// Clear out our logfile (so any old data is overwritten)
	fstream fs; 
	fs.open(g_logfile, fstream::out);
	fs.close();

	// instantiate our conmgr which will handle all communications with the WDs
	ConnectionManager conMgr(numWatchdogs, g_logfile); 

	/** Establish connection to all WDs **/
	if (!conMgr.EstablishWDConnections()) // establish connection to all WDs
	{
		cout << "Unable to establish connection to WDs" << endl;
		return 0;
	}

	/** Send start signal to all watchdogs **/
	if (!conMgr.SendStartSignal())
	{
		cout << "Unable to send start signal" << endl;
		return 0;
	}

	/** MAIN APPLICATION LOOP - Receive reports for all WDs then process them **/
	while (1)
	{
		vector<string> reports;
		if (!conMgr.ReceiveWDReports(reports)) // ReceiveWDReports returns FALSE when all watchdogs have finished/dc'ed		
		{
			cout << "Exiting..." << endl;
			return 0;
		}
		ProcessReports(reports);
	}

	return 0; // Shouldn't ever get here
}

