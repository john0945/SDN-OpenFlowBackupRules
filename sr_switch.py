
class sr_switch():

    def __init__(self, SID):
        self.SID = SID
        self.neighbours = {}

    #use the port as the key, since it will be unique for this switch - neighbour might be connected with two links/ports
    def add_neighbours(self, port, new_neigh):
        self.neighbours[port] = new_neigh

    def has_neighbour(self, SID):
        if SID in self.neighbours.values():
            return True
        else:
            return False


