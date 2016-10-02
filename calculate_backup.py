import logging
import pprint
pp = pprint.PrettyPrinter()

LOG = logging.getLogger(__name__)

#input the shortest path tree for the switch in question, as well as the reverse shortest path for
#the destination in question, as well as the 'failed' link
def calculate_backup(spt, dest_rspt, link):
    print("")