using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using PcapDotNet.Base;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using PcapDotNet.Packets.Http;

namespace ConsoleApp
{
    class Program
    {
        private static int TcpCounts = 0;
        private static int IcmpCounts = 0;
        private static int UdpCounts = 0;
        private static int other = 0;
        private static int maxLength = 0;
        private static int minLength = 0;
        private static int avgLength = 0;
        private static int DfragmentCount = 0;
        private static Dictionary<string, int> packetCountsForAddress = new Dictionary<string, int>();
        private static Dictionary<string, int> tcpPorts = new Dictionary<string, int>() {
            {"FTP(SSl)" , 0} , {"SSH",0},{ "Telnet",0},{"SMTP",0 },{"HTTP(s)" , 0} , {"POP3",0},{ "IMAP",0},{"DNS",0 },{"other",0 }
        };
        private static Dictionary<string, int> udpPorts = new Dictionary<string, int>() {
            {"DNS" , 0} , {"DHCP",0},{ "TFTP",0},{"NTP",0 },{"other",0 }
        };
        static void Main(string[] args)
        {
            IList<LivePacketDevice> allDevice = LivePacketDevice.AllLocalMachine;
            if (allDevice.Count == 0)
            {
                Console.WriteLine("Install Winpcap!");
            }
            for (int i = 0; i < allDevice.Count; i++)
            {
                LivePacketDevice device = allDevice[i];
                Console.WriteLine($"{i + 1} , {device.Name}");
                if (device.Description != null)
                {
                    Console.Write($"( {device.Description} )");
                }
                Console.WriteLine();
            }
            int deviceIndex = 0;
            do
            {
                Console.WriteLine($"Enter the interface number (1-{allDevice.Count}):");
                string deviceIndexString = Console.ReadLine();
                if (!int.TryParse(deviceIndexString, out deviceIndex) || deviceIndex < 1 || deviceIndex > allDevice.Count)
                {
                    deviceIndex = 0;
                }
            } while (deviceIndex == 0);
            PacketDevice selectedDevice = allDevice[deviceIndex - 1];
            Console.WriteLine("Source\t\tDestination\t\tProtocol\t\tLength");
            Thread thr = new Thread(() => sniffer(selectedDevice));
            thr.Start();
            string s = Console.ReadLine();
            if (s.Equals("c"))
            {
                thr.Abort();
                StringBuilder result = new StringBuilder("TCP: ");
                result.Append(TcpCounts + " | UDP: ");
                result.Append(UdpCounts + " | ICMP: ");
                result.Append(IcmpCounts + " | Other: ");
                result.AppendLine($"{ other}");
                var items = from pair in packetCountsForAddress
                            orderby pair.Value descending
                            select pair;
                ;
                result.AppendLine("      Source               Packets");
                int i = 1;
                foreach (KeyValuePair<string, int> pair in items)
                {
                    result.AppendLine(string.Format("{0,-3}.  {1,-16} | {2,5}", i, pair.Key, pair.Value));
                    i++;
                }
                result.AppendLine($"fragments: {TcpCounts + UdpCounts + IcmpCounts + other - DfragmentCount}");
                result.AppendLine($"Min length: {minLength} | Average length: {avgLength / (other + IcmpCounts + TcpCounts + UdpCounts)} | Max length: {maxLength}");
                result.AppendLine("*******************");

                result.AppendLine($"TCP Protocols:");
                foreach (string t in tcpPorts.Keys)
                {
                    result.AppendLine($"{t}: {tcpPorts[t]}");

                }
                result.AppendLine("*******************");
                result.AppendLine($"UDP Protocols:");
                foreach (string t in udpPorts.Keys)
                {
                    result.AppendLine($"{t}: {udpPorts[t]}");

                }
                using (StreamWriter writer = new StreamWriter(@".\result.txt"))
                {
                    writer.WriteLine(result.ToString());

                }
                Console.WriteLine(result.ToString());
                Console.ReadKey();
            }
        }
        private static void PacketHandler(Packet packet)
        {
            IpV4Datagram ip = packet.Ethernet.IpV4;
            //protocols
            if (ip.Protocol == IpV4Protocol.Tcp)
            {
                TcpCounts++;
                bool check = true;
                switch (ip.Tcp.SourcePort)
                {
                    case 20:
                    case 21:
                    case 989:
                    case 990:
                        tcpPorts["FTP(SSl)"]++;
                        break;
                    case 22:
                        tcpPorts["SSH"]++;
                        break;
                    case 23:
                        tcpPorts["Telnet"]++;
                        break;
                    case 25:
                        tcpPorts["SMTP"]++;
                        break;
                    case 53:
                        tcpPorts["DNS"]++;
                        break;
                    case 80:
                    case 443:
                        tcpPorts["HTTP(s)"]++;
                        break;
                    case 110:
                        tcpPorts["POP3"]++;
                        break;
                    case 143:
                        tcpPorts["IMAP"]++;
                        break;
                    default:
                        check = false;
                        break;
                }
                if (!check)
                {
                    switch (ip.Tcp.DestinationPort)
                    {
                        case 20:
                        case 21:
                        case 989:
                        case 990:
                            tcpPorts["FTP(SSl)"]++;
                            break;
                        case 22:
                            tcpPorts["SSH"]++;
                            break;
                        case 23:
                            tcpPorts["Telnet"]++;
                            break;
                        case 25:
                            tcpPorts["SMTP"]++;
                            break;
                        case 53:
                            tcpPorts["DNS"]++;
                            break;
                        case 80:
                        case 443:
                            tcpPorts["HTTP(s)"]++;
                            break;
                        case 110:
                            tcpPorts["POP3"]++;
                            break;
                        case 143:
                            tcpPorts["IMAP"]++;
                            break;
                        default:
                            tcpPorts["other"]++;
                            break;
                    }
                }
            }
            else if (ip.Protocol == IpV4Protocol.InternetControlMessageProtocol)
            {
                IcmpCounts++;
            }
            else if (ip.Protocol == IpV4Protocol.Udp)
            {
                UdpCounts++;

                bool check = true;
                switch (ip.Udp.SourcePort)
                {
                    case 67:
                    case 68:
                        udpPorts["DHCP"]++;
                        break;
                    case 69:
                        udpPorts["TFTP"]++;
                        break;
                    case 123:
                        udpPorts["NTP"]++;
                        break;
                    case 53:
                        udpPorts["DNS"]++;
                        break;
                    default:
                        check = false;
                        break;
                }
                if (!check)
                {
                    switch (ip.Udp.DestinationPort)
                    {
                        case 67:
                        case 68:
                            udpPorts["DHCP"]++;
                            break;
                        case 69:
                            udpPorts["TFTP"]++;
                            break;
                        case 123:
                            udpPorts["NTP"]++;
                            break;
                        case 53:
                            udpPorts["DNS"]++;
                            break;
                        default:
                            udpPorts["other"]++;
                            break;
                    }
                }
            }
            else
            {
                other++;
            }
            //packet length
            avgLength += packet.Length;
            if (packet.Length > maxLength)
            {
                maxLength = packet.Length;
            }
            if (packet.Length < minLength || minLength == 0)
            {
                minLength = packet.Length;
            }
            //fragments
            if (ip.Fragmentation.Options == IpV4FragmentationOptions.DoNotFragment)
            {
                DfragmentCount++;
            }
            //ip and their packets
            if (packetCountsForAddress.ContainsKey(ip.Source.ToString()))
            {
                packetCountsForAddress[ip.Source.ToString()]++;
            }
            else
            {
                packetCountsForAddress.Add(ip.Source.ToString(), 1);
            }
            //loging
            Console.WriteLine($"{ip.Source}\t{ip.Destination}\t{ip.Protocol}\t{packet.Length}");
        }
        public static void sniffer(PacketDevice selectedDevice)
        {
            using (PacketCommunicator communicator = selectedDevice.Open(65536, PacketDeviceOpenAttributes.DataTransferUdpRemote, 1000))
            {
                Console.WriteLine("Listening on {0} ...", selectedDevice.Description);
                communicator.ReceivePackets(0, PacketHandler);
            }
        }

    }
}
