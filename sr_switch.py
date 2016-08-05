
class sr_switch():

    def __init__(self, SID):
        self.SID = SID
        self.neighbours = {}   # port : neighbour
        self.groups = {}       # SID : group ID

    #use the port as the key, since it will be unique for this switch - neighbour might be connected with two links/ports
    def add_neighbours(self, port, new_neigh):
        self.neighbours[port] = new_neigh

    def has_neighbour(self, SID):
        if SID in self.neighbours.values():
            return True
        else:
            return False

    def get_port(self, SID):
        if self.has_neighbour(SID):
            return [port for port,neigh in self.neighbours.items() if neigh == SID]
        else:
            return '-1'

    def add_group(self, SID, group):
        self.groups[SID] = group
