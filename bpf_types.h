enum _ethertype
{
    IPv4 = 0x0800,
    IPv6 = 0x86dd
};

struct etherpkt
{
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    enum _ethertype ethertype;
    uint8_t payload[];
};