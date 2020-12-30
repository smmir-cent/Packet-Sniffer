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
        private static int fragmentCount = 0;
        private static Dictionary<string,int> packetCountsForAddress = new Dictionary<string, int>();
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
                result.AppendLine($"fragments: {fragmentCount}");
                result.AppendLine($"Min length: {minLength} | Average length: {avgLength/(other+IcmpCounts+TcpCounts+UdpCounts)} | Max length: {maxLength}");
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

            if (ip.Protocol == IpV4Protocol.Tcp)
            {
                TcpCounts++;
            }
            else if (ip.Protocol == IpV4Protocol.InternetControlMessageProtocol)
            {
                IcmpCounts++;
            }
            else if (ip.Protocol == IpV4Protocol.Udp)
            {
                UdpCounts++;
            }
            else
            {
                other++;
            }

            avgLength += packet.Length;
            if (packet.Length > maxLength)
            {
                maxLength = packet.Length;
            }
            if (packet.Length < minLength || minLength==0)
            {
                minLength = packet.Length;
            }

            if (ip.Fragmentation.Options == IpV4FragmentationOptions.DoNotFragment)
            {
                fragmentCount++;
            }
            if (packetCountsForAddress.ContainsKey(ip.Source.ToString()))
            {
                packetCountsForAddress[ip.Source.ToString()]++;
            }
            else
            {
                packetCountsForAddress.Add(ip.Source.ToString(),0);
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
