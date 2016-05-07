#ifndef TRAFFIC_ANALYZER_H
#define TRAFFIC_ANALYZER_H

#include <string>
#include <map>
#include <vector>
#include <tuple>

using namespace std;


/** @brief 5-tuple of src_ip, dst_ip, src_port, dst_port, and protocol */
typedef tuple<string, string, int, int, string> flow_t;

/** @brief Category of alerts */
enum AlertType { PACKETS, BYTES, FLOWS };


/** @brief Stores all relevant metadata for a single packet */
struct PacketInfo
{
	/** Size of packet in bytes */
	int size; 		

	/** Source IP address in dot-quad notation */
	string src_ip; 

	/** Destination IP address in dot-quad notation */	
	string dst_ip; 	

	/** Source port number (0 if packet protocol is not TCP/UDP) */
	int src_port; 

	/** Destination port number (0 if packet protocol is not TCP/UDP) */
	int dst_port; 

	/** Protocol ('TCP', 'UDP', 'ICMP', 'IP') */
	string protocol; 
};


/** @brief Used by the watchdogs to handle all processing of packet data

	Takes packets as input via AddPacket() method, then generates a report via the GenerateReport() 
	method. Packet data is stored within a TrafficData struct (declared as a private member
	within TrafficAnalyzer). Packet data is accumulated per destination and stored within the m_dstTrafficMap 
	(that is, there is one TrafficData instance per destination IP Address containing the total sum of 
	bytes/packets/flows for all packets added with that destination IP). This allows TrafficAnalyzer to easily 
	determine the offending destination IP in the event that an alert is detected. 

	Once the GenerateReport() method is called (at the end of each timeslice), a report is generated with all 
	data within the m_dstTrafficMap and saved to the m_prevData member variable. The m_dstTrafficMap is then cleared.
	*/
class TrafficAnalyzer
{

private:

	/** @brief Internal struct within TrafficAnaluyzer containing a number of packets/bytes and list of flows */
	struct TrafficData
	{
		/** Number of packets added */
		int packets;

		/** Sum of the size of all packets added (in bytes) */	
		int bytes;

		/** List of unique flows added */
		vector<flow_t> flows; 

		/** @brief Constructor
			Initializes packets and bytes to 0.
			*/
		TrafficData()
		{
			packets = 0;
			bytes = 0;
		}

		/** @brief Adds packet data to the existing counts 
			
			Increments packet count and adds packet size to the bytes count, then adds
			the packet's flow to the list of flows if it does not already exist within the flows list.

			@param size size of the packet in bytes.
			@param flow the packet's flow.
			*/
		void AddPacketData(int size, flow_t flow)
		{
			packets++;
			bytes += size;

			// add flow to flows list if an entry doesnt already exist
			for (unsigned int i = 0; i < flows.size(); i++)	
			{
				if (flows[i] == flow)
				{
					return;
				}	
			}
			flows.push_back(flow);
		}

		/** Overload of the addition assignment operator, adds packet and byte counts of rhs to this, and
			concatenates rhs's flows list to this flows list.

			@param rhs the right hand side TrafficData instance to add to this

			@return reference to the sum of this += rhs 
			*/
		TrafficData& operator+=(const TrafficData& rhs)
		{
			this->packets += rhs.packets;
			this->bytes += rhs.bytes;

			this->flows.insert(this->flows.end(), rhs.flows.begin(), rhs.flows.end());

			return *this;
		}

		/**	Overload of the addition operator (see operator+= overload for explanation)

			@param rhs the right hand side addend to be summed with this

			@return the sum of this + rhs
			*/
		const TrafficData operator+(const TrafficData& rhs) const
		{
			return TrafficData(*this) += rhs;
		}
	};

	/** The name of the file to log to */
	string m_logfile;	

	/** Total traffic data for this timeslice (seperated and mapped by dst) */
	map<string, TrafficData> m_dstTrafficMap;	
	
	/** Total accumulated traffic data from the previous timeslice */
	TrafficData m_prevData;	
	
	/** Number of reports that have been generated */
	int m_reportsGenerated;						


	/** @brief Appends a message to m_logfile and console */
	void LogMessage(const string& msg) const;

	/** @brief Checks traffic data to see if an alert has been generated */
	bool CheckAlert(const TrafficData& trafficData, bool alertFlags[3]) const;

	


public:

	/** @brief Constructor **/
	TrafficAnalyzer(const string& logfile);

	/** @brief Adds packet to be processed **/
	void AddPacket(const PacketInfo& p);

	/** @brief Generates and returns a report about all traffic data since last call to GenerateReport() **/
	string GenerateReport();


};

#endif