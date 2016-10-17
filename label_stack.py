def get(fw, path):
    stack = []
    spt_d = fw[path[-1]]
    spt_s = fw[path[1]] # we're actually checking the behaviour of the first neighbour on the route

    hops = len(path)-1
    q = hops    #the destination node will definitely 'reach' itself
    p = 1 # the neighbouring node is definitely in the extended p-space
    for x in range (1, hops+1):
        test = path[(hops-x):hops+1]
        test.reverse()
        if test in spt_d.values():
            q = hops-x
            #print('found q' + str(q))

        else:
            #print ('found not q')
            break
    for y in range(2, q+1):
        test = path[1:y+1]
        if test in spt_s.values():
            p = y
            #print('found p' + str(p))

        else:
            #print('found not p')
            break


    diff = p - q
    if diff ==0:
        if p != 1:
            stack.append(path[p])
    else:
        for i in range(p,q+1):
            if i != 1:
                stack.append(path[i])

    print(len(stack))
    print(stack)
    return stack

