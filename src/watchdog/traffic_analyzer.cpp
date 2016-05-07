#include "traffic_analyzer.h"

#include <sstream>
#include <iostream>
#include <fstream>



/** @param msg The message to be written to m_logfile and console. 
	*/
void TrafficAnalyzer::LogMessage(const string& msg) const
{
	fstream fs; 
	fs.open(m_logfile, fstream::out | fstream::app);
	fs << msg << endl;
	fs.close();

	cout << msg << endl;
}


/** Called internally by GenerateReport() method. Checks trafficData against data from the
	previous report (stored in member variable m_prevData) to see if traffic is anomolous. 
	If trafficData has more than 3x as many packets, alerts, or flows as m_prevData, an 
	an alert is detected and alertFlags are set accordingly (indicating whether the 
	alert was due to packets, bytes, and/or flows).

	@param[in] trafficData The traffic data to scan for anomolous data
	@param[out] alertFlags An array of three bools (whose indices correspond to the AlertType enum)
				that are set to TRUE if an alert was detected for that category (e.g. packets/bytes/flows)
	
	@return TRUE if an alert was detected and FALSE otherwise 
	*/
bool TrafficAnalyzer::CheckAlert(const TrafficData& trafficData, bool alertFlags[3]) const
{
	alertFlags[PACKETS] = trafficData.packets > (m_prevData.packets * 3);
	alertFlags[BYTES] = trafficData.bytes > (m_prevData.bytes * 3);
	alertFlags[FLOWS] = trafficData.flows.size() > (m_prevData.flows.size() * 3);

	return alertFlags[PACKETS] || alertFlags[BYTES] || alertFlags[FLOWS];
}


/** Initializes TrafficAnalyzer instance with number of watchdogs to connect to and the name of file to log to. 
	
	@param logfile Name of the logfile that relevent info will be logged to 
	*/
TrafficAnalyzer::TrafficAnalyzer(const string& logfile)
{
	m_logfile = logfile;
	m_reportsGenerated = 0;
}


/** Adds a packet to be processed. First determines the flow of the packet, then 
	adds the packet to the TrafficMap instance corresponding the packets destination. 

	@param p PacketInfo struct storing all relevent metadata from a packet
	*/
void TrafficAnalyzer::AddPacket(const PacketInfo& p)
{
	flow_t flow = make_tuple(p.src_ip, p.dst_ip, p.src_port, p.dst_port, p.protocol);

	// Add packet info to traffic map using dst as key (keep track of traffic data per dst)
	m_dstTrafficMap[p.dst_ip].AddPacketData(p.size, flow);
}


/** To be called at the end of each timeslice. Sums data from all packets added (via AddPacket() method)
	since the last call to GenerateReport(). The total traffic data for this time slice is then
	checked for alerts (via CheckAlert() method) and a report is generated and returned. 

	Before returning, the m_dstTrafficMap member variable is cleared out and the traffic data totals
	are saved into the m_prevData member variable.

	@return The traffic report for all packets added since last call to GenerateReport()
	*/
string TrafficAnalyzer::GenerateReport()
{
	int reportId = ++m_reportsGenerated;

	// sum all of our traffic data and determine dst w/ most packets, bytes, flows.
	TrafficData totalData;
	string dstWithMostPackets, dstWithMostBytes, dstWithMostFlows;
	int mostPackets=0, mostBytes=0, mostFlows=0;

	for (auto it = m_dstTrafficMap.begin(); it != m_dstTrafficMap.end(); it++)
	{
		TrafficData data = it->second;

		totalData += data;

		if (data.packets > mostPackets)
		{
			dstWithMostPackets = it->first;
			mostPackets = data.packets;
		}
		if (data.bytes > mostBytes)
		{
			dstWithMostBytes = it->first;
			mostBytes = data.bytes;
		}
		if (data.flows.size() > (unsigned)mostFlows)
		{
			dstWithMostFlows = it->first;
			mostFlows = data.flows.size();
		}
	}

	// assemble report string and log 
	ostringstream ossReport;
	bool alertFlags[3] = {false};
	
	if (CheckAlert(totalData, alertFlags))	// checks if alert triggered of and what type(s)
	{
		ostringstream ossAlertLog; // (e.g. "alert packets flows")
		ossAlertLog << "alert";
		ossReport << "alert ";
		if (alertFlags[PACKETS]) ossAlertLog << " packets";
		if (alertFlags[BYTES]) ossAlertLog << " bytes";
		if (alertFlags[FLOWS]) ossAlertLog << " flows";
		LogMessage(ossAlertLog.str()); // log alert
	}

	ossReport << "report " << reportId << " ";
	ossReport << totalData.packets << " " << totalData.bytes << " " << totalData.flows.size();

	// append ip address of dst that triggered alert
	if (alertFlags[PACKETS]) ossReport << " " << dstWithMostPackets;
	else if (alertFlags[BYTES]) ossReport << " " << dstWithMostBytes;
	else if (alertFlags[FLOWS]) ossReport << " " << dstWithMostFlows;

	LogMessage(ossReport.str()); // log report

	// update previous traffic data for next time and clear out current data
	m_prevData = totalData;
	m_dstTrafficMap.clear();
	
	return ossReport.str();
}

