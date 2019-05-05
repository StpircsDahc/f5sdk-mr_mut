#!/usr/bin/python2
from mr_mut import *
import yaml
import sys


def argv_failure():
    logging.error("\r\n"*3)
    logging.error("     This script requires command line arguments to run.")
    logging.error("     Please submit either 'build' or 'destroy' directives as [argv1] when executing this script.")
    logging.error("     Please submit authorized iControl password as [argv2] when executing this script.")
    logging.critical("  ABORTING ....")
    logging.critical("\r\n"*3)
    exit()


#main
if __name__ == "__main__":
    # set the logging level for this run (most elements are logged to INFO and WARNING)
    logger.setLevel(logging.ERROR)
    # Verify required command line arguments have been provided
    if len(sys.argv) < 3:
        argv_failure()
    ## define connection parameters for F5 appliances
    # defaultF5 = ManagementRoot("192.168.1.245", 'admin', 'admin')
    try:
        labF5 = ManagementRoot("172.16.1.5", 'admin', sys.argv[2])
    except:
        # Give friendly feedback when bad credentials are provided
        ICR_error = str(sys.exc_info()[1])
        logging.critical(ICR_error[:38] + " error!!")
        logging.critical('Invalid ICR credentials provided!!')
        argv_failure()
    # Make sure we are working on the active unit
    if not isActiveF5(labF5):
        logging.error("\r\n"*3)
        logging.error("     This device is not the 'active' appliance.")
        logging.error("     Please connect to the active appliance before continuing.")
        logging.critical("     ABORTING ....")
        logging.critical("\r\n"*3)
        exit()


    ## define yaml template file
    # Expect the yaml file to have the same naming convention as the script (Ansible style)
    if sys.argv[0][: 2] == "./":
        yamFile = sys.argv[0][2: -3] + ".yaml"
    else:
        yamFile = sys.argv[0][0: -3] + ".yaml"

    # Establish data set from yaml file
    with open(yamFile, 'r') as stream:
        try:
            yamData = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            logging.critical(exc)

    # establish data containers
    vs = yamData['wip']['virtual']
    pool = yamData['wip']['pool']
    nodes = yamData['wip']['nodes']

    if sys.argv[1] == "build":
    ################
    ## demo build ##
    ################
    # build the nodes
        for node in nodes:
            create_new_node(labF5, node['name'], node['ipAddr'], node['descr'], node['monitor'])

    # build the pool
        create_new_pool(labF5, pool['name'], pool['descr'], pool['monitor'], pool['lbMethod'], pool['minMembers'])

    # add members to the newly created pool
        countemup = 0
        for node in nodes:
            countemup +=1
            memDescr = "F5 python SDK --- Demo member " + str(countemup)
            member = node['ipAddr'] + ":" + pool['svcPort']
            add_pool_member(labF5, pool['name'], member, memDescr, pool['memMonitor'], node['PriGrp'])

    # build the virtual server
        vsDestination = vs['destIP'] + ":" + vs['destPORT']
        create_new_VS(labF5,vs['name'], vsDestination, vs['destMASK'], pool['name'], vs['vlans'], vs['profiles'], vs['rules'], vs['snat'], vs['protocol'])


    elif sys.argv[1] == "destroy":
    ##################
    ## demo destroy ##
    ##################
    # destroy the virtual server
        delete_existing_virtual(labF5, vs['name'], 'Common')
    # destroy the pool
        delete_existing_pool(labF5, pool['name'], 'Common')
    # destroy the nodes
        for node in nodes:
            delete_existing_node(labF5, node['name'], 'Common')


    else:
        argv_failure()
