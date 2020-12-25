using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
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
        static void Main(string[] args)
        {
            IList<LivePacketDevice> allDevice = LivePacketDevice.AllLocalMachine;
            if (allDevice.Count == 0)
            {
                Console.WriteLine("Install Winpcap!");
            }
            for(int i = 0;i< allDevice.Count;i++)
            {
                LivePacketDevice device = allDevice[i];
                Console.WriteLine($"{i+1} , {device.Name}");
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
                if (!int.TryParse(deviceIndexString , out deviceIndex) || deviceIndex<1 || deviceIndex >allDevice.Count)
                {
                    deviceIndex = 0;
                }
            } while (deviceIndex==0);
            PacketDevice selectedDevice = allDevice[deviceIndex - 1];

            Console.WriteLine("Enter the Filter(ip and tcp) , (ip and udp) , (tcp) , (udp) , icmp , port 80");
            string filter = Console.ReadLine();
            using (PacketCommunicator communicator = selectedDevice.Open(65536, PacketDeviceOpenAttributes.DataTransferUdpRemote, 1000))
            {
                Console.WriteLine("Listening on {0} ...", selectedDevice.Description);
                communicator.SetFilter(filter);

                communicator.ReceivePackets(0, PacketHandler);

            }
        }

        private static void PacketHandler(Packet pkt)
        {
            IpV4Datagram ip = pkt.Ethernet.IpV4;
            Console.WriteLine($"IP Header Source:{ip.Source} Destination:{ip.Destination} Protocol:{ip.Protocol} TTL:{ip.Ttl}");
        }
    }
}
