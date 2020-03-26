#include <stdio.h>
#include <pcap.h>


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    printf("i have got a packet\n");
}
int main (int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;    /* Session handle */
    char dev[] = "en0";
    struct bpf_program fp; /* The compiled filter expression */
    char filter_exp[] = "ip"; /* The filter expression */
    bpf_u_int32 mask;   /* The netmask of our sniffing device */
    bpf_u_int32 net;    /* The IP of our sniffing device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL){
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 0;
    }
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 0;
    }
    if (pcap_setfilter(handle, &fp) == -1){
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return 0;
    }
    // dev = pcap_lookupdev(errbuf);
    // if (dev == NULL)
    // {
    //     fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
    //     return 0;
    // }
    pcap_loop(handle, 5, got_packet, NULL);
    // printf("Device: %s\n", dev);
    return 0;

}


