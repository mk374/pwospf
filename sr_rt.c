/*-----------------------------------------------------------------------------
 * file:  sr_rt.c
 * date:  Mon Oct 07 04:02:12 PDT 2002
 * Author:  casado@stanford.edu
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>


#include <sys/socket.h>
#include <netinet/in.h>
#define __USE_MISC 1 /* force linux to show inet_aton */
#include <arpa/inet.h>

#include "sr_rt.h"
#include "sr_if.h"
#include "sr_utils.h"
#include "sr_router.h"
#include "sr_arpcache.h"

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

int sr_load_rt(struct sr_instance* sr,const char* filename)
{
    FILE* fp;
    char  line[BUFSIZ];
    char  dest[32];
    char  gw[32];
    char  mask[32];    
    char  iface[32];
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;
    int clear_routing_table = 0;

    /* -- REQUIRES -- */
    assert(filename);
    if( access(filename,R_OK) != 0)
    {
        perror("access");
        return -1;
    }

    fp = fopen(filename,"r");

    while( fgets(line,BUFSIZ,fp) != 0)
    {
        sscanf(line,"%s %s %s %s",dest,gw,mask,iface);
        if(inet_aton(dest,&dest_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    dest);
            return -1; 
        }
        if(inet_aton(gw,&gw_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    gw);
            return -1; 
        }
        if(inet_aton(mask,&mask_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    mask);
            return -1; 
        }
        if( clear_routing_table == 0 ){
            printf("Loading routing table from server, clear local routing table.\n");
            sr->routing_table = 0;
            clear_routing_table = 1;
        }
        sr_add_rt_entry(sr,dest_addr,gw_addr,mask_addr,(uint32_t)0,iface);
    } /* -- while -- */

    return 0; /* -- success -- */
} /* -- sr_load_rt -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/
int sr_build_rt(struct sr_instance* sr){
    struct sr_if* interface = sr->if_list;
    char  iface[32];
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;

    while (interface){
        dest_addr.s_addr = (interface->ip & interface->mask);
        gw_addr.s_addr = 0;
        mask_addr.s_addr = interface->mask;
        strcpy(iface, interface->name);
        sr_add_rt_entry(sr, dest_addr, gw_addr, mask_addr, (uint32_t)0, iface);
        interface = interface->next;
    }
    return 0;
}

void sr_add_rt_entry(struct sr_instance* sr, struct in_addr dest,
struct in_addr gw, struct in_addr mask, uint32_t metric, char* if_name)
{   
    struct sr_rt* rt_walker = 0;

    /* -- REQUIRES -- */
    assert(if_name);
    assert(sr);

    pthread_mutex_lock(&(sr->rt_lock));
    /* -- empty list special case -- */
    if(sr->routing_table == 0)
    {
        sr->routing_table = (struct sr_rt*)malloc(sizeof(struct sr_rt));
        assert(sr->routing_table);
        sr->routing_table->next = 0;
        sr->routing_table->dest = dest;
        sr->routing_table->gw   = gw;
        sr->routing_table->mask = mask;
        strncpy(sr->routing_table->interface,if_name,sr_IFACE_NAMELEN);
        sr->routing_table->metric = metric;
        time_t now;
        time(&now);
        sr->routing_table->updated_time = now;

        pthread_mutex_unlock(&(sr->rt_lock));
        return;
    }

    /* -- find the end of the list -- */
    rt_walker = sr->routing_table;
    while(rt_walker->next){
      rt_walker = rt_walker->next; 
    }

    rt_walker->next = (struct sr_rt*)malloc(sizeof(struct sr_rt));
    assert(rt_walker->next);
    rt_walker = rt_walker->next;

    rt_walker->next = 0;
    rt_walker->dest = dest;
    rt_walker->gw   = gw;
    rt_walker->mask = mask;
    strncpy(rt_walker->interface,if_name,sr_IFACE_NAMELEN);
    rt_walker->metric = metric;
    time_t now;
    time(&now);
    rt_walker->updated_time = now;
    
     pthread_mutex_unlock(&(sr->rt_lock));
} /* -- sr_add_entry -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_table(struct sr_instance* sr)
{
    pthread_mutex_lock(&(sr->rt_lock));
    struct sr_rt* rt_walker = 0;

    if(sr->routing_table == 0)
    {
        printf(" *warning* Routing table empty \n");
        pthread_mutex_unlock(&(sr->rt_lock));
        return;
    }
    printf("  <---------- Router Table ---------->\n");
    printf("Destination\tGateway\t\tMask\t\tIface\tMetric\tUpdate_Time\n");

    rt_walker = sr->routing_table;
    
    while(rt_walker){
        if (rt_walker->metric < INFINITY)
            sr_print_routing_entry(rt_walker);
        rt_walker = rt_walker->next;
    }
    pthread_mutex_unlock(&(sr->rt_lock));


} /* -- sr_print_routing_table -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_entry(struct sr_rt* entry)
{
    /* -- REQUIRES --*/
    assert(entry);
    assert(entry->interface);
    
    char buff[20];
    struct tm* timenow = localtime(&(entry->updated_time));
    strftime(buff, sizeof(buff), "%H:%M:%S", timenow);
    printf("%s\t",inet_ntoa(entry->dest));
    printf("%s\t",inet_ntoa(entry->gw));
    printf("%s\t",inet_ntoa(entry->mask));
    printf("%s\t",entry->interface);
    printf("%d\t",entry->metric);
    printf("%s\n", buff);

} /* -- sr_print_routing_entry -- */

void *sr_rip_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    while (1) {
        sleep(5);
        pthread_mutex_lock(&(sr->rt_lock));
        /* Fill your code here */

        struct sr_if *interface_list = sr->if_list;
        struct sr_rt *head_rt_node = sr->routing_table;
        struct in_addr dest_addr;
        struct in_addr gw_addr;
        struct in_addr mask_addr;

        while (interface_list) {
            uint32_t old_status = interface_list->status;
            uint32_t curr_status = sr_obtain_interface_status(sr, interface_list->name);            
            
            if (old_status == 0) {
                if (curr_status == 1) {
                    dest_addr.s_addr = (interface_list->ip & interface_list->mask);
                    gw_addr.s_addr = 0;
                    mask_addr.s_addr = interface_list->mask;
                    char  iface[32];
                    strcpy(iface, interface_list->name);

                    interface_list->status = curr_status;
                    sr_add_rt_entry(sr, dest_addr, gw_addr, mask_addr, (uint32_t) 0, iface);
                }
            } 
            if (old_status == 1) { 
                struct sr_rt* current = head_rt_node;

                while (current) {
                    if (current->metric < INFINITY) {
                        int routing_table_match = 0;
                        if ((interface_list->ip & interface_list->mask) == (current->dest.s_addr & interface_list->mask)) {
                            routing_table_match = 1;
                        }
                        if ((strcmp(current->interface, interface_list->name) == 0)
                                && (routing_table_match == 1)
                                && (current->gw.s_addr == 0)
                                && (interface_list->mask == current->mask.s_addr)) {
                            if (curr_status == 0) {
                                interface_list->status = curr_status; /* different, so change */
                                current->metric = htonl(INFINITY);
                            } else { /* curr_status = 1 */
                                /* curr_status and old_status are same */
                                time_t now;
                                time(&now);
                                current->updated_time = now;
                            }
                        } 
                    }
                    current = current->next;
                }               
            }
            interface_list = interface_list->next;
        }

        struct sr_rt *node = head_rt_node;

        while(node) {
            if (node->metric < INFINITY) {
                time_t now;
                time(&now);
                if (difftime(now, node->updated_time) > 20.0) {
                    
                    node->metric = htonl(INFINITY);
                } 
            }
            node = node->next;
        }
        send_rip_update(sr);
        sr_print_routing_table(sr);
        pthread_mutex_unlock(&(sr->rt_lock));
    }
    return NULL;
}

void send_rip_request(struct sr_instance *sr){

    struct sr_if *interface = sr->if_list;
    int header_len = sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t);
    while (interface) {
        uint8_t *rip_packet = (uint8_t *) malloc(header_len);
        sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t *) rip_packet;
        sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*) (rip_packet + sizeof(sr_ethernet_hdr_t));
        sr_udp_hdr_t *udp_hdr = (sr_udp_hdr_t *) (rip_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        sr_rip_pkt_t *rip_pkt = (sr_rip_pkt_t*) (rip_packet + sizeof(sr_udp_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        ethernet_hdr->ether_type = htons(ethertype_ip);
        memset(ethernet_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN); 
        memcpy(ethernet_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);

        ip_hdr->ip_v = 4;
        ip_hdr->ip_hl = 5;
        ip_hdr->ip_id = 0;
        ip_hdr->ip_off = 0;
        ip_hdr->ip_ttl = INIT_TTL;
        ip_hdr->ip_p = ip_protocol_udp;
        ip_hdr->ip_src = interface->ip;
        ip_hdr->ip_dst = inet_addr("255.255.255.255");
        ip_hdr->ip_len = htons(header_len - sizeof(sr_ethernet_hdr_t));
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

        udp_hdr->udp_len = htons(sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t));
        udp_hdr->port_dst = htons(520); 
        udp_hdr->port_src = htons(520);
        udp_hdr->udp_sum = 0;

        rip_pkt->version = 2;
        rip_pkt->command = 1;

        rip_pkt->entries[0].afi = htons(0); /* per rfc2453*/
        rip_pkt->entries[0].address = htonl(interface->ip);
        rip_pkt->entries[0].metric = htonl(INFINITY);

        sr_send_packet(sr, rip_packet, header_len, interface->name);
        free(rip_packet);

        interface = interface->next;
    }
}

void send_rip_update(struct sr_instance *sr){
    pthread_mutex_lock(&(sr->rt_lock));
    /* Fill your code here */
    struct sr_if *interface = sr->if_list;
    int header_len = sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t);
    while (interface) {
        uint8_t *rip_packet = (uint8_t *) malloc(header_len);
        sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t *) rip_packet;
        sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*) (rip_packet + sizeof(sr_ethernet_hdr_t));
        sr_udp_hdr_t *udp_hdr = (sr_udp_hdr_t *) (rip_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        sr_rip_pkt_t *rip_pkt = (sr_rip_pkt_t*) (rip_packet + sizeof(sr_udp_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        ethernet_hdr->ether_type = htons(ethertype_ip);
        memset(ethernet_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN); 
        memcpy(ethernet_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);

        ip_hdr->ip_v = 4;
        ip_hdr->ip_hl = 5;
        ip_hdr->ip_id = 0;
        ip_hdr->ip_off = 0;
        ip_hdr->ip_ttl = INIT_TTL;
        ip_hdr->ip_p = ip_protocol_udp;
        ip_hdr->ip_src = interface->ip;
        ip_hdr->ip_dst = inet_addr("255.255.255.255");
        ip_hdr->ip_len = htons(header_len - sizeof(sr_ethernet_hdr_t));
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

        udp_hdr->udp_len = htons(sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t));
        udp_hdr->port_dst = htons(520); 
        udp_hdr->port_src = htons(520);
        udp_hdr->udp_sum = 0;

        rip_pkt->version = 2;
        rip_pkt->command = 2;
    
        struct sr_rt *rt = sr->routing_table;
        int i = 0;
        while(rt && (i < MAX_NUM_ENTRIES)) {
            rip_pkt->entries[i].address = rt->dest.s_addr;
            rip_pkt->entries[i].mask = rt->mask.s_addr;
            rip_pkt->entries[i].next_hop = rt->gw.s_addr;
            rip_pkt->entries[i].tag = 0;
            rip_pkt->entries[i].afi = htons(2);

            if((rt->gw.s_addr & rt->mask.s_addr) != (interface->ip & interface->mask)) {
                rip_pkt->entries[i].metric = htonl(rt->metric);
            } else{
                rip_pkt->entries[i].metric = htonl(INFINITY);
            }
            i++;
            rt = rt->next;
        }

        sr_send_packet(sr, rip_packet, header_len, interface->name);
        free(rip_packet);

        interface = interface->next;
    }
    pthread_mutex_unlock(&(sr->rt_lock));
}

int check_interface(struct sr_instance *sr, struct entry *entry){
    struct sr_if *interface = sr->if_list;

    while(interface) {
        if((interface->ip & interface->mask) == (entry->address & entry->mask)){
            return 1;
        }

        interface = interface->next;
    }

    return 0;
}

void update_route_table(struct sr_instance *sr, sr_ip_hdr_t* ip_packet,
        sr_rip_pkt_t* rip_packet, char* iface) {
    pthread_mutex_lock(&(sr->rt_lock));
    /* Fill your code here */
    bool updated = false;
    int i = 0;
    while(i < MAX_NUM_ENTRIES){
        struct entry *entry = &rip_packet->entries[i];
            

        if(entry->address != 0 && entry->address != 127 && (check_interface(sr,entry) == 0)){
            int m = ntohl(entry->metric);
            if(m+1 > INFINITY){
                entry->metric = htonl(INFINITY);
            } else{
                entry->metric = htonl(m+1);
            }

            struct sr_rt *explicit_route = NULL;
            struct sr_rt *rt_node = sr->routing_table;
            while(rt_node){
                if((rt_node->dest.s_addr & rt_node->mask.s_addr) == (entry->address & entry->mask)){
                    explicit_route = rt_node;
                    break;
                }

                rt_node = rt_node->next;
            }

            if(!explicit_route && ntohl(entry->metric) < INFINITY){
                struct in_addr dest_addr;
                struct in_addr gw_addr;
                struct in_addr mask_addr;

                dest_addr.s_addr = entry->address & entry->mask;
                gw_addr.s_addr = ip_packet->ip_src;
                mask_addr.s_addr = entry->mask;

                sr_add_rt_entry(sr, dest_addr, gw_addr, mask_addr, entry->metric, iface);
                updated = true;
            } else{
                if(ntohl(entry->metric) < explicit_route->metric ||
                    (explicit_route->gw.s_addr == ip_packet->ip_src && explicit_route->metric != ntohl(entry->metric))){
                    explicit_route->metric = ntohl(entry->metric);
                    time_t now;
                    time(&now);
                    explicit_route->updated_time = now;
                    explicit_route->gw.s_addr = ip_packet->ip_src;
                    strcpy(explicit_route->interface, iface);
                    updated = true;
                }
            }

        }

        i++;

    }

    if(updated){
        printf("Route Table Updated, Sending Triggered Update\n");
        send_rip_update(sr);
    } else{
        printf("No Updates\n");
    }

    pthread_mutex_unlock(&(sr->rt_lock));
}
