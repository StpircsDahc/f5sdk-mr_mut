#!/usr/bin/python2
from mr_mut import *
import getpass
#
#
if __name__ == "__main__":
    ## define connection parameters for F5 appliance
    authorized_user = 'admin'
    # user_passwd = 'admin'
    user_passwd = getpass.getpass(ICR password:)
    #
    ## Establish connection to target F5
    # f5a = ManagementRoot("192.168.1.245", authorized_user, user_passwd)
    f5a = ManagementRoot("172.16.1.5", authorized_user, user_passwd)
#
#
    # # do stuff with the connection
    if isActiveF5(f5a):
        print "This device is the 'active' device."
    #
    # add_sys_ntp(f5a, ['0.us.pool.ntp.org', '1.us.pool.ntp.org', '2.us.pool.ntp.org', '3.us.pool.ntp.org'])
    #
    # delete_sys_ntp(f5a)
    #
    # add_sys_nameServers(f5a, ['8.8.8.8', '8.8.4.4'])
    # add_sys_dnsSearch(f5a, ['dahclab.local', 'dahclab.com'])
    #
    # delete_sys_nameServers(f5a)
    # delete_sys_dnsSearch(f5a)
    # #
    # create_new_node(f5a, "cb_test_node_1", "8.8.8.1")
    # create_new_node(f5a,  "cb_test_node_2", "8.8.4.2")
    #
    # delete_existing_node(f5a,  "cb_test_node_1")
    # delete_existing_node(f5a,  "cb_test_node_2")
    #
    # create_new_pool(f5a, 'cb_test42_PL', "SDK - test pool for Chad Bohannan Demo","gateway_icmp")
    # #
    # add_pool_member(f5a, 'cb_test42_PL', '8.8.8.8:53', 'cb_test_node_1')
    # add_pool_member(f5a, 'cb_test42_PL', '8.8.4.4:53', 'cb_test_node_2')
    #
    # delete_existing_pool(f5a, "cb_test42_PL")
    #
    # all_nodes_summary(f5a)
    # # #
    # all_pools_summary(f5a)
    # #
    # all_virtuals_summary(f5a)
    # #
    # isPoolMember(f5a, 'cb_test_node_1')
    # #
    # applied_to_list = is_applied_profile(f5a, "http")
    # for x in applied_to_list:
    #     print x
    # #
    # #
    # replaced_list = replace_profile_with(f5a, "clientssl", "example.com_SSL_client")
    # #
    # all_iApps = iApp_managed(f5a)
    # for app in all_iApps:
    #     print app
    # is_iApp = iApp_managed(f5a, "Splunk_tcp_logging_vs")
    # print is_iApp
