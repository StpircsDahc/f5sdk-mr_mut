#!/usr/bin/python2
# # Suggested reading
# # https://devcentral.f5.com/articles/getting-started-with-the-f5-common-python-sdk-27438
# # https://devcentral.f5.com/articles/getting-started-with-the-python-sdk-part-2-unnamed-resources-and-commands-27602
# # https://devcentral.f5.com/articles/getting-started-with-the-python-sdk-part-3-working-with-statistics-31387
# # https://devcentral.f5.com/articles/getting-started-with-the-python-sdk-part-4-working-with-request-parameters-31420
# # https://devcentral.f5.com/articles/getting-started-with-the-python-sdk-part-5-request-parameters-revisited-31509
# # https://devcentral.f5.com/articles/getting-started-with-the-python-sdk-part-6-transactions-31951
# # https://clouddocs.f5.com/products/extensions/f5-appsvcs-extension/latest/

import re
#
import logging
logging.root.handlers = []
logger = logging.getLogger()
logger.setLevel(logging.CRITICAL)
#
from f5.bigip import ManagementRoot
from pprint import pprint as pp # for pretty print of json data
#
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
#
'''
github.com/stpircsdahc
##~~~~~~~~~~~~~~~~~~~~~~~~~~~~~##
#!  dahc's Useless F5 toolkit  !#
##~~~~~~~~~~~~~~~~~~~~~~~~~~~~~##
'''
#
#
###########
##  DELETE  ##
###########

def delete_existing_node(connection, nName, nPartition='Common'):
    if connection.tm.ltm.nodes.node.exists(name=nName, partition=nPartition) and not isPoolMember(connection, nName, nPartition):
        nuke_node = connection.tm.ltm.nodes.node.load(name=nName, partition=nPartition)
        try:
            nuke_node.delete()
            logging.info(nName + " nuked!!!")
            return None
        except Exception as printable_obj:
            return printable_obj
    elif connection.tm.ltm.nodes.node.exists(name=nName, partition=nPartition) and isPoolMember(connection, nName, nPartition):
        poolConsumers = isPoolMember(connection, nName, nPartition)
        logging.warning('node ' + nName + ' is a member of pool(s)!!!')
        for x in poolConsumers:
            logging.warning('>>  ' +  x)
        logging.warning('Aborting node deletion for node: ' + nName)
    else:
        # print "node %s doesn't exist!!!\nAborting...\n..\n.\n" % nName
        return False
#
#
def delete_existing_pool(connection, pool_name, partition='Common'):
    ## Delete a pool if it exists
    if connection.tm.ltm.pools.pool.exists(name=pool_name, partition=partition):
        nuke_pool = connection.tm.ltm.pools.pool.load(name=pool_name, partition=partition)
        nuke_pool.delete()
        logging.info(pool_name + " nuked!!!")
    else:
        logging.warning('pool ' + pool_name + " doesn't exist!!")
        logging.warning('Aborting pool deletion for pool: ' + pool_name)
#
#
def delete_existing_virtual(connection, virtual_name, partition='Common'):
    ## Delete a virtual server if it exists
    if connection.tm.ltm.virtuals.virtual.exists(name=virtual_name, partition=partition):
        nuke_vs = connection.tm.ltm.virtuals.virtual.load(name=virtual_name, partition=partition)
        nuke_vs.delete()
        logging.info(virtual_name + ' nuked!!!')
    else:
        logging.warning('virtual server ' + virtual_name + " doesn't exist!!")
        logging.warning('Aborting VS deletion for VS: ' + virtual_name)
#
#
def delete_existing_datagroup(connection, dgl_name, partition='Common'):
    ## retrieve a list[] of all datagroup objects
    all_datagroup_list = connection.tm.ltm.data_group.internals.get_collection()
    ## iterate data group lists, find target dgl_name
    for dgl in all_datagroup_list:
        if dgl.name == dgl_name:
            dgl.delete()
            logging.info(dgl_name + ' nuked!!!')
    all_dataGroups = all_datagroups_summary(connection)
    dglNames=[]
    for dgl in all_dataGroups:
        for name in dgl:
            dglNames.append(name)
    if dgl_name in dglNames:
        return False
    else:
        return True
#
#
###########
##  CREATE  ##
###########
def create_new_node(connection, nName, nAddress, nDescription=None, nMonitor="default", nPartition='Common'):
    if is_IPv4(nAddress):
        if not connection.tm.ltm.nodes.node.exists(name=nName,  partition=nPartition):
            mknode = connection.tm.ltm.nodes.node.create(name=nName, description=nDescription, address=nAddress, monitor=nMonitor, partition=nPartition)
            if nDescription:
                logging.info('Node created: ' + nName + ':' + nAddress + ':' + nDescription + ':' + nPartition)
            else:
                logging.info('Node created: ' + nName + ':' + nAddress + ':' + nPartition)
        else:
            logging.warning('node ' + nName +' already exists!!!')
            logging.warning('Aborting node creation for node: ' + nName)
    else:
        logging.warning('Invalid node IP address ' + nAddress + ' supplied!!!')
        logging.warning('Aborting node creation for node: ' + nName)
#
#
def create_new_pool(connection, pName, pDescription, pMonitor='gateway_icmp', pLBmode='least-connections-member',  minActMems=0, pPartition='Common'):
    if not connection.tm.ltm.pools.pool.exists(name=pName, partition=pPartition):
        mkpool = connection.tm.ltm.pools.pool.create(name=pName, description=pDescription, monitor=pMonitor, \
            loadBalancingMode=pLBmode, minActiveMembers=minActMems, partition=pPartition)
        logging.info('pool created: ' + pName + ':' + pDescription + ':' + pPartition)
    else:
        logging.warning('pool ' + pName + ' already exists!!!')
        logging.warning('Aborting pool creation for pool : ' + pName)
#
#
def create_new_VS(connection, vName, vDstAddr, vMask, vPool=None, vVlans=None, \
    vProfiles=None, vRules=None, vSnat="on", vProtocol='tcp', vPartition='Common'):
    #
    #
    address = vDstAddr.split(":")[0]
    if is_IPv4(address):
        if not connection.tm.ltm.virtuals.virtual.exists(name=vName, partition=vPartition):
            if vSnat == "on":
                vipSnat = {'type':'automap'}
            elif vSnat == "off":
                vipSnat = {'type':'none'}
            else:
                vipSnat = {'type':'snat', 'pool':vSnat}
            #
            if vVlans:
                # vVlansState = True
                vVlansState = False
            else:
                vVlansState = False
            #
            #
            result = connection.tm.ltm.virtuals.virtual.create( \
                name=vName , destination=vDstAddr, mask=vMask, sourceAddressTranslation=vipSnat, \
                pool=vPool, vlansEnabled=vVlansState,vlans=vVlans, profiles=vProfiles, rules=vRules, \
                ipProtocol=vProtocol, partition=vPartition)
            if result.vsIndex:
                logging.info('Virtual server ' + vName + ' with address ' + vDstAddr + ' created!!')
                return result.vsIndex
            else:
                return False
        else:
            logging.warning('Virtual server ' + vName + ' already exists!!!')
            logging.warning('Aborting VS creation for VS : ' + vName)
    else:
        logging.warning('Invalid node IP address ' + address + ' supplied!!!')
        logging.warning('Aborting VS creation for VS : ' + vName)
#
#
def create_new_datagroup(connection, dgl_name, dgl_type, dgl_records, dgPartition='Common'):
    new_datagroup_list = connection.tm.ltm.data_group.internals.internal.create(name=dgl_name, type=dgl_type, records=dgl_records, partition=dgPartition)
    all_dataGroups = all_datagroups_summary(connection)
    dglNames=[]
    for dgl in all_dataGroups:
        for name in dgl:
            dglNames.append(name)
    if dgl_name in dglNames:
        logging.info('DataGroup List ' + dgl_name + ' created!!')
        return True
    else:
        logging.warning('Failed to create DataGroup List: ' + dgl_name)
        logging.warning('Unspecified error occoured in DataGroup List creation process.')
        logging.warning('Aborting creation of DataGroup List: ' + dgl_name)
        return False
#
#
###########
##  MODIFY  ##
###########
def add_pool_member(connection, pName, mDstAddr, mDescription=" ", mMonitor='default', mPgroup=0, pPartition='Common'):
    address = mDstAddr.split(":")[0]
    if is_IPv4(address):
        if connection.tm.ltm.pools.pool.exists(name=pName, partition=pPartition):
            target_pool = connection.tm.ltm.pools.pool.load(name=pName, partition=pPartition)
            target_mems = target_pool.members_s.get_collection()
            memAddrs = []
            for mem in target_mems:
                memAddrs.append(mem.address)
            nodes = connection.tm.ltm.nodes.get_collection()
            nodeAddrs = {}
            for node in nodes:
                nodeAddrs[node.address] = node.name
            if address in memAddrs:
                logging.warning('Pool member ' + mDstAddr + ' already exists in pool ' + pName + '!!!')
            elif address in nodeAddrs:
                new_address = nodeAddrs[address] + ":" + mDstAddr.split(":")[1]
                target_pool.members_s.members.create(name=new_address, description=mDescription, \
                    monitor=mMonitor, priorityGroup=mPgroup, partition=pPartition)
                target_pool.update()
                logging.info('Member ' + mDstAddr + ' added to pool ' + pName + '!!!')
            else:
                target_pool.members_s.members.create(name=mDstAddr, description=mDescription, \
                    monitor=mMonitor, partition=pPartition)
                target_pool.update()
                logging.info('Member ' + mDstAddr + ' crated and added to pool ' + pName + '!!!')
    else:
        logging.warning('Invalid member IP address ' + address + ' supplied!!!')
        logging.warning('Aborting! Member ' + mDstAddr + ' NOT added to pool ' + pName + '!!!')
#
#
def replace_profile_with(connection, old_profileName, new_profileName, new_profile_partition='Common'):
    appliedProfiles_list = []
    appliedProfiles_modified = []
    iApp_exclusions = ["Splunk_tcp_logging_vs"]
    virtuals = connection.tm.ltm.virtuals.get_collection()
    for virtual in virtuals:
        vName = virtual.name
        vPartition = virtual.partition
        if vName not in iApp_exclusions: # temp fix ...address iapps later
            Target_vs = connection.tm.ltm.virtuals.virtual.load(partition=vPartition, name=vName)
            for profile in virtual.profiles_s.get_collection():
                if profile.name == old_profileName and vName not in appliedProfiles_list:
                    appliedProfiles_list.append(vName)
                    migrate_context = profile.context
                    profile.delete()
                    Target_vs.update()
                    virtual.profiles_s.profiles.create(name=new_profileName, context=migrate_context, partition=new_profile_partition)
                    Target_vs.update()
            for profile in virtual.profiles_s.get_collection():
                if profile.name == new_profileName and vName in appliedProfiles_list:
                    logging.info(virtual.name + "'s profile(" + profile.name + ") has been updated!!")
    return appliedProfiles_list
#
#
def add_peristence(connection, vName, vPersist, vFallbackPersist=None, vPartition='Common'):
    if connection.tm.ltm.virtuals.virtual.exists(name=vName, partition=vPartition):
        target_VS = connection.tm.ltm.virtuals.virtual.load(name=vName, partition=vPartition)
        target_VS.modify(persist=vPersist, fallbackPersistence=vFallbackPersist)
        target_VS.update()
#
#
def add_datagroup_record(connection, dgl_name, new_recordName, new_recordData, dglPartition='Common'):
    ## establish the new record
    new_record = {'data':new_recordData, 'name':new_recordName}
    ## retrieve a list[] of all datagroup objects
    all_datagroup_list = connection.tm.ltm.data_group.internals.get_collection()
    ## iterate data group lists, find target dgl_name
    for dgl in all_datagroup_list:
        if dgl.name == dgl_name:
            new_records = dgl.records
            new_records.append(new_record)
            dgl.update(name=dgl_name, records=new_records)
            logging.info('DataGroup List ' + dgl_name + ' has been updated with new record ' + new_recordName)
#
#
def del_datagroup_record(connection, dgl_name, dgl_recordName, dglPartition='Common'):
    ## retrieve a list[] of all datagroup objects
    all_datagroup_list = connection.tm.ltm.data_group.internals.get_collection()
    ## iterate data group lists, find target dgl_name
    for dgl in all_datagroup_list:
        if dgl.name == dgl_name:
            new_records = []
            for record in dgl.records:
                if record['name'] != dgl_recordName:
                    new_records.append(record)
            dgl.update(name=dgl_name, records=new_records)
            logging.info('Record ' + dgl_recordName + ' has been deleted from DataGroup List ' + dgl_name)
#
#
##########
##  LEARN  ##
##########
def isPoolMember(connection, nName, nPartition='Common'):
    ## Search through all pools to see if given node (nName) is a member of any pools
    ## Returns None,  or list of pools where node is consumed
    pools = connection.tm.ltm.pools.get_collection(requests_params={'params': {'expandSubcollections':'true'}})
    pMembers = []
    for pool in pools:
        pPath = pool.fullPath
        if "items" in pool.membersReference.iterkeys():
            for member in pool.membersReference['items']:
                # if nName.lower() == member["address"].lower():
                mName = member["name"].split(":")[0].lower()
                if nName.lower() == mName:
                    pMembers.append(pPath)
    if len(pMembers) > 0:
        for pm in pMembers:
            logging.info('Node ' + nName + ' is a member of pool' + pm + '!!!')
        return pMembers
    else:
        logging.info('Node ' + nName + ' is a not a member of any pools!!!')
        return None
#
#
def all_nodes_summary(connection):
    # ## Get a list of all nodes on the BigIP and print their names
    nodes = connection.tm.ltm.nodes.get_collection()
    for node in nodes:
        p = node.partition
        n = node.name
        a = node.address
        m = node.monitor
        try:
            d=node.description
            logging.info('Node ' + p + '/' + n + ' has description of ' + d + ' and an address of ' + a + ' with a monitor of ' + m)
        except AttributeError:
            logging.info('Node ' + p + '/' + n + ' has an address of ' + a + ' with a monitor of ' + m + ' and does not have a description')
#
#
def all_pools_summary(connection):
    ## Get a list of all pools on the BigIP and print their names and their members' names
    pools = connection.tm.ltm.pools.get_collection()
    for pool in pools:
        pPath = pool.fullPath
        pLBmode = pool.loadBalancingMode
        try:
            pMonitor = pool.monitor
        except:
            AttributeError
            pMonitor = "None"
        pMembers = []
        for member in pool.members_s.get_collection():
            mPath = member.fullPath
            mAddress = member.address
            mMonitor = member.monitor
            pMembers.append(mPath + "___" + mAddress + "___" + mMonitor)
        logging.info('Pool ' + pPath + ' is configured with an LBmode of ' + pLBmode + ' and the following member details.')
        for x in pMembers:
            values = x.split("___")
            logging.info('     Pool member: ' + values[0])
            logging.info('     Pool address: ' + values[1])
            logging.info('     Pool monitor: ' + values[2])
#
#
def iApp_managed(connection, VS_name=None):
    iApp_exclusions = []
    virtuals = connection.tm.ltm.virtuals.get_collection()
    for virtual in virtuals:
        try:
            isApp = virtual.appServiceReference
            iApp_exclusions.append(virtual.name)
        except:
            #not iApp managed
            pass
    if not VS_name:
        return iApp_exclusions
    else:
        if VS_name in iApp_exclusions:
            return True
        else:
            return False
#
#
def all_virtuals_summary(connection):
    ## collect virtual server information and print a summary
    virtuals = connection.tm.ltm.virtuals.get_collection()
    counter = 0
    for vip in virtuals:
        vName = vip.name
        vPartition = vip.partition
        vPath = vip.fullPath
        vDestination = vip.destination
        vProtocol = vip.ipProtocol
        vSrcNat = vip.sourceAddressTranslation['type']
        vDestination = vip.destination.split("/")[-1]
#
        vProfiles_list = []
        vPolicies_list = []
        vPoolMember_list = []
        vTarget_vs = connection.tm.ltm.virtuals.virtual.load(partition=vPartition, name=vName)
#
        ## Test VS for existing attributes
        try:
            vRules = vip.rules
        except:
            AttributeError
            vRules = False
        try:
            for profile in vTarget_vs.profiles_s.get_collection():
                vProfiles_list.append(profile.fullPath)
        except:
            AttributeError
            vProfiles = "None"
        try:
            for policy in vTarget_vs.policies_s.get_collection():
                vPolicies_list.append(policy.fullPath)
        except:
            AttributeError
            vProfiles = "None"
        try:
            vPool = vip.pool
            pool_full_path = vip.pool.split("/")
            vTarget_pool = connection.tm.ltm.pools.pool.load(partition=pool_full_path[1], name=pool_full_path[2])
            for member in vTarget_pool.members_s.get_collection():
                try:
                    vPoolMember_list.append(member.fullPath)
                except:
                    AttributeError
                    vPoolMember_list.append("None")
        except:
            AttributeError
            vPool = "None"
        try:
            vDescription = vip.description
        except:
            AttributeError
            vDescription = "None"
#
        logging.info('     Virtual server ' + vPath + ' is configured with:')
        logging.info('     Description: ' + vDescription)
        logging.info('     Destination: ' + vDestination)
        logging.info('     Protocol: ' + vProtocol)
        logging.info('     SNAT type: ' + vSrcNat)
        if vRules:
            logging.info('     With the following rules: ')
            for x in vRules:
                logging.info('     < ' + x + ' >')
#
        if len(vProfiles_list) >= 1:
            logging.info('     and the following profiles: ')
            for x in vProfiles_list:
                logging.info('     < ' + x + ' >')
#
        if len(vPolicies_list) >= 1:
            logging.info('     and the following policies: ')
            for x in vPolicies_list:
                logging.info('     < ' + x + ' >')
#
        if len(vPoolMember_list) >= 1:
            logging.info('     and includes these pool members: ')
            for x in vPoolMember_list:
                logging.info('     < ' + x + ' >')
#
#
def all_datagroups_summary(connection, printer=False):
    ## retrieve a list[] of all datagroup objects
    all_datagroup_list = connection.tm.ltm.data_group.internals.get_collection()
    ## iterate data group lists, find target dgl_name
    dgl_names = []
    for dgl in all_datagroup_list:
        dglName = dgl.name
        dglRecords = dgl.records
        dglFull = dgl.fullPath
        dglType = dgl.type
        if printer:
            logging.info(' DataGroup List ' + dglName + ' of type ' + dglType + ' was found (' + dglFull + ')!!')
            logging.info(dglName + ' contains the following records...')
            for dict in dglRecords:
                logging.info('     name:' + dict['name'] + ',data:' + dict['data'])
        dgl_names.append({dglName:dglRecords})
        # print "%s:%s" % (dglName,dglRecords)
    return dgl_names
#
#
def is_applied_profile(connection, target_profileName):
    appliedProfiles_list = []
    iApp_exclusions = iApp_managed(connection)
    virtuals = connection.tm.ltm.virtuals.get_collection()
    for virtual in virtuals:
        vName = virtual.name
        vPartition = virtual.partition
        if vName not in iApp_exclusions:
            vTarget_vs = connection.tm.ltm.virtuals.virtual.load(partition=vPartition, name=vName)
            try:
                for profile in virtual.profiles_s.get_collection():
                    if profile.name == target_profileName and vName not in appliedProfiles_list:
                        appliedProfiles_list.append(vName)
            except:
                # print " NO PROFILES HIT"
                pass
    return appliedProfiles_list
#
#
def get_datagroup_records(connection, dgl_name):
    ## retrieve a list[] of all datagroup objects
    all_datagroup_list = connection.tm.ltm.data_group.internals.get_collection()
    ## iterate data group lists, find target dgl_name
    for dgl in all_datagroup_list:
        if dgl.name == dgl_name:
            ## return the records associated with target dgl_name
            return dgl.records
#
#
#############
##  UnNamed's  ##
#############
# The following functions primarly interact with 'unNamed resources
# unNamed resources do not allow create, or delete functionality like named resources (such as pools, nodes)
# In most scenarios, the actions will replace(all) existing configurations '
def add_sys_nameServers(connection, NSlist):
    sys_dns = connection.tm.sys.dns.load()
    # pp(sys_dns.raw)
    sys_dns.nameServers = NSlist
    sys_dns.update()
    for NS in NSlist:
        logging.info(NS + " added to system's name server list!!")
#
#
def delete_sys_nameServers(connection):
    sys_dns = connection.tm.sys.dns.load()
    for NS in sys_dns.nameServers:
        logging.info(NS + " removed from system's name server list!!")
    sys_dns.nameServers = []
    sys_dns.update()
#
#
def add_sys_dnsSearch(connection, searchlist):
    sys_dns = connection.tm.sys.dns.load()
    searchlist.append('localhost')
    sys_dns.search = searchlist
    sys_dns.update()
    for suffix in searchlist:
        if not suffix == 'localhost':
            logging.info(suffix + " added to system's search order list!!")
#
#
def delete_sys_dnsSearch(connection):
    sys_dns = connection.tm.sys.dns.load()
    for suffix in sys_dns.search:
        if not suffix  == 'localhost':
            logging.info(suffix + " removed from system's search order list!!")
    sys_dns.search = ['localhost']
    sys_dns.update()
#
#
def add_sys_ntp(connection, ntplist):
    sys_ntp = connection.tm.sys.ntp.load()
    sys_ntp.servers = ntplist
    sys_ntp.update()
    for server in ntplist:
        logging.info(server + " added to system's ntp server list!!")
#
#
def delete_sys_ntp(connection):
    sys_ntp = connection.tm.sys.ntp.load()
    for server in sys_ntp.servers:
        logging.info(server + " removed from system's ntp server list!!")

    sys_ntp.servers = []
    sys_ntp.update()
#
#
##########
##  MISC  ##
##########
def isActiveF5(connection):
    foStatus = connection.tm.sys.failover.load()
    device_fo_status = foStatus.apiRawValues['apiAnonymous'].split(" ")[1]
    if device_fo_status.lower() == "active":
        return True
    else:
        return False
#
#
def is_IPv4(ip_addr):
    ip = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")
    if ip.match(ip_addr):
        return True
    else:
        return False
#
#
def sync_HA(connection, sync_group_name):
    # ## sync the changes to the HA group
    # ## example sync_group_name = 'F5_HA_synch-failover-group'
    sync_cmd = 'config-sync to-group ' +  sync_group_name
    connection.tm.cm.exec_cmd('run', utilCmdArgs=sync_cmd)
