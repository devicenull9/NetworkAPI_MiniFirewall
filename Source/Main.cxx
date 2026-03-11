/**
 * NetworkAPI plugin to implement a mini firewall
 *
 * @note This plugin uses a O(n) complexity, that means it is not fast enough for high-performance applications, network perfomance/speed might degrade
 *
 * @license Apache 2.0
 */

#include <iostream>
#include <string>
#include <fstream>
#include <vector>

#include "CCommon.hxx"
#include "NetworkAPI.hxx"
#include "CForwards.hxx"

#include "SDK/json.hpp"

std::string global_plugin_name = "NetworkAPI_MiniFirewall";
std::string global_plugin_version = "1.0.0";
std::string global_plugin_author = "NetworkAPI Development Team";

using json = nlohmann::json;

struct Rule_IPv4
{
    uint32_t start_address;
    uint32_t end_address;

    uint8_t protocol;

    std::vector<uint16_t> port_table;
};

struct Rule_IPv6
{
    uint8_t prefix[16];
    uint8_t prefix_length;

    uint8_t protocol;

    std::vector<uint16_t> port_table;
};

std::vector<Rule_IPv4> global_rule_table_ipv4;
std::vector<Rule_IPv6> global_rule_table_ipv6;

bool global_allow_mode = false;

bool IsInPrefix(const uint8_t ip_address[16], const uint8_t prefix[16], uint8_t prefix_length)
{
    uint8_t full_bytes = prefix_length / 8;

    for (uint8_t iterator = 0; iterator < full_bytes; ++iterator)
    {
        if (ip_address[iterator] != prefix[iterator])
            return false;
    }

    uint8_t remaining_bits = prefix_length % 8;

    if (remaining_bits > 0)
    {
        uint8_t mask = (0xff << (8 - remaining_bits)) & 0xff;
        
        if ((ip_address[full_bytes] & mask) != (prefix[full_bytes] & mask))
            return false;
    }

    return true;
}

void LoadConfiguration()
{
    std::ifstream input_file_stream("NetworkAPI_MiniFirewall_Configuration.json");

    if (!input_file_stream)
    {
        std::cerr << CCommon_ConsoleText_Red << "[NetworkAPI:Plugin/Error] [" << global_plugin_name << "] Error parsing configuration file" << CCommon_ConsoleText_Default << std::endl;

        return;
    }

    json json_root_object;

    input_file_stream >> json_root_object;

    if (json_root_object.contains("networkapi_minifirewall"))
    {
        global_allow_mode = json_root_object["networkapi_minifirewall"]["allow_mode"].get<bool>();

        auto &json_array_rule_table = json_root_object["networkapi_minifirewall"]["rule_table"];

        for (const auto &json_array_rule_table_item: json_array_rule_table)
        {
            if (json_array_rule_table_item["ip_version"].get<uint8_t>() == 4)
            {
                struct in_addr address_1;
                struct in_addr address_2;

                inet_pton(AF_INET, json_array_rule_table_item["ip_address"]["start"].get<std::string>().c_str(), &address_1);
                inet_pton(AF_INET, json_array_rule_table_item["ip_address"]["end"].get<std::string>().c_str(), &address_2);

                Rule_IPv4 rule = {};

                rule.start_address = ntohl(address_1.s_addr);
                rule.end_address = ntohl(address_2.s_addr);

                rule.protocol = json_array_rule_table_item["protocol"].get<uint8_t>();

                if (rule.protocol != IPPROTO_ICMP)
                {
                    auto &json_array_port_table = json_array_rule_table_item["port_table"];

                    for (const auto &json_array_port_table_item : json_array_port_table)
                        rule.port_table.push_back(json_array_port_table_item.get<uint16_t>());
                }

                global_rule_table_ipv4.push_back(rule);
            }

            else if (json_array_rule_table_item["ip_version"].get<uint8_t>() == 6)
            {
                uint8_t prefix[16] = {};

                inet_pton(AF_INET6, json_array_rule_table_item["prefix"].get<std::string>().c_str(), prefix);

                Rule_IPv6 rule = {};

                memcpy(rule.prefix, prefix, 16);

                rule.prefix_length = json_array_rule_table_item["prefix_length"].get<uint8_t>();

                rule.protocol = json_array_rule_table_item["protocol"].get<uint8_t>();

                if (rule.protocol != IPPROTO_ICMPV6)
                {
                    auto &json_array_port_table = json_array_rule_table_item["port_table"];

                    for (const auto &json_array_port_table_item : json_array_port_table)
                        rule.port_table.push_back(json_array_port_table_item.get<uint16_t>());
                }

                global_rule_table_ipv6.push_back(rule);
            }
        }
    }

    else
    {
        std::cerr << CCommon_ConsoleText_Red << "[NetworkAPI:Plugin/Error] [" << global_plugin_name << "] Error parsing configuration file" << CCommon_ConsoleText_Default << std::endl;

        return;
    }
}

CForwards_PluginExport CForwards_ForwardResult On_PluginInit()
{
    std::cout << CCommon_ConsoleText_Green << "[NetworkAPI:Plugin]" << CCommon_ConsoleText_Default << " On_PluginInit" << std::endl;
    std::cout << CCommon_ConsoleText_Green << "[NetworkAPI:Plugin]" << CCommon_ConsoleText_Default << " - Name: " << global_plugin_name << std::endl;
    std::cout << CCommon_ConsoleText_Green << "[NetworkAPI:Plugin]" << CCommon_ConsoleText_Default << " - Version: " << global_plugin_version << std::endl;
    std::cout << CCommon_ConsoleText_Green << "[NetworkAPI:Plugin]" << CCommon_ConsoleText_Default << " - Author: " << global_plugin_author << std::endl;

    LoadConfiguration();

    return CForwards_ForwardResult::Forward_Ignored;
}

CForwards_PluginExport CForwards_ForwardResult On_PluginEnd()
{
    std::cout << CCommon_ConsoleText_Green << "[NetworkAPI:Plugin]" << CCommon_ConsoleText_Default << " On_PluginEnd" << std::endl;
    std::cout << CCommon_ConsoleText_Green << "[NetworkAPI:Plugin]" << CCommon_ConsoleText_Default << " - Name: " << global_plugin_name << std::endl;
    std::cout << CCommon_ConsoleText_Green << "[NetworkAPI:Plugin]" << CCommon_ConsoleText_Default << " - Version: " << global_plugin_version << std::endl;
    std::cout << CCommon_ConsoleText_Green << "[NetworkAPI:Plugin]" << CCommon_ConsoleText_Default << " - Author: " << global_plugin_author << std::endl;

    return CForwards_ForwardResult::Forward_Ignored;
}

CForwards_PluginExport CForwards_ForwardResult On_PacketReceive_IPv4(NetworkAPI_PacketMetadata *packet_metadata, unsigned char *packet, int *packet_length, unsigned char *data, int *data_length, NetworkAPI_PacketHeader_IPv4 *ipv4_header, NetworkAPI_PacketHeader_TCP *tcp_header, NetworkAPI_PacketHeader_UDP *udp_header, NetworkAPI_PacketHeader_ICMP *icmp_header)
{
    uint32_t ip_address = 0;

    uint16_t port = 0;

    if (packet_metadata->incoming_device > 0 && packet_metadata->outgoing_device == 0)
    {
        ip_address = ntohl(ipv4_header->source_address);

        if (tcp_header != nullptr)
            port = ntohs(tcp_header->source_port);

        else if (udp_header != nullptr)
            port = ntohs(udp_header->source_port);
    }

    else if (packet_metadata->outgoing_device > 0 && packet_metadata->incoming_device == 0)
    {
        ip_address = ntohl(ipv4_header->destination_address);

        if (tcp_header != nullptr)
            port = ntohs(tcp_header->destination_port);

        else if (udp_header != nullptr)
            port = ntohs(udp_header->destination_port);
    }

    bool found_ip_address = false;

    for (const auto &rule_table_item : global_rule_table_ipv4)
    {
        if (ip_address >= rule_table_item.start_address && ip_address <= rule_table_item.end_address)
            found_ip_address = true;

        if (rule_table_item.protocol != IPPROTO_ICMP)
        {
            for (const auto &rule_port_table_item : rule_table_item.port_table)
            {
                if (found_ip_address)
                {
                    if (rule_table_item.protocol == IPPROTO_TCP && tcp_header != nullptr && rule_port_table_item == port)
                    {
                        if (global_allow_mode)
                            return CForwards_ForwardResult::Forward_Ignored;

                        else
                            return CForwards_ForwardResult::Forward_Supersede;
                    }

                    else if (rule_table_item.protocol == IPPROTO_UDP && udp_header != nullptr && rule_port_table_item == port)
                    {
                        if (global_allow_mode)
                            return CForwards_ForwardResult::Forward_Ignored;

                        else
                            return CForwards_ForwardResult::Forward_Supersede;
                    }
                }
            }
        }

        else
        {
            if (found_ip_address)
            {
                if (global_allow_mode)
                    return CForwards_ForwardResult::Forward_Ignored;

                else
                    return CForwards_ForwardResult::Forward_Supersede;
            }
        }
    }

    return global_allow_mode ? CForwards_ForwardResult::Forward_Supersede : CForwards_ForwardResult::Forward_Ignored;
}

CForwards_PluginExport CForwards_ForwardResult On_PacketReceive_IPv6(NetworkAPI_PacketMetadata *packet_metadata, unsigned char *packet, int *packet_length, unsigned char *data, int *data_length, NetworkAPI_PacketHeader_IPv6 *ipv6_header, NetworkAPI_PacketHeader_TCP *tcp_header, NetworkAPI_PacketHeader_UDP *udp_header, NetworkAPI_PacketHeader_ICMPv6 *icmpv6_header)
{
    uint8_t ip_address[16] = {};

    uint16_t port = 0;

    if (packet_metadata->incoming_device > 0 && packet_metadata->outgoing_device == 0)
    {
        memcpy(ip_address, ipv6_header->source_address, 16);

        if (tcp_header != nullptr)
            port = ntohs(tcp_header->source_port);

        else if (udp_header != nullptr)
            port = ntohs(udp_header->source_port);
    }

    else if (packet_metadata->outgoing_device > 0 && packet_metadata->incoming_device == 0)
    {
        memcpy(ip_address, ipv6_header->destination_address, 16);

        if (tcp_header != nullptr)
            port = ntohs(tcp_header->destination_port);

        else if (udp_header != nullptr)
            port = ntohs(udp_header->destination_port);
    }

    bool found_ip_address = false;

    for (const auto &rule_table_item : global_rule_table_ipv6)
    {
        if (IsInPrefix(ip_address, rule_table_item.prefix, rule_table_item.prefix_length))
            found_ip_address = true;

        if (rule_table_item.protocol != IPPROTO_ICMPV6)
        {
            for (const auto &rule_port_table_item : rule_table_item.port_table)
            {
                if (found_ip_address)
                {
                    if (rule_table_item.protocol == IPPROTO_TCP && tcp_header != nullptr && rule_port_table_item == port)
                    {
                        if (global_allow_mode)
                            return CForwards_ForwardResult::Forward_Ignored;

                        else
                            return CForwards_ForwardResult::Forward_Supersede;
                    }

                    else if (rule_table_item.protocol == IPPROTO_UDP && udp_header != nullptr && rule_port_table_item == port)
                    {
                        if (global_allow_mode)
                            return CForwards_ForwardResult::Forward_Ignored;

                        else
                            return CForwards_ForwardResult::Forward_Supersede;
                    }
                }
            }
        }

        else
        {
            if (found_ip_address)
            {
                if (global_allow_mode)
                    return CForwards_ForwardResult::Forward_Ignored;

                else
                    return CForwards_ForwardResult::Forward_Supersede;
            }
        }
    }

    return global_allow_mode ? CForwards_ForwardResult::Forward_Supersede : CForwards_ForwardResult::Forward_Ignored;
}
