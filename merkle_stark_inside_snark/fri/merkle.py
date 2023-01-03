from hashlib import blake2b

class MerkleTree:
    H = blake2b

    def commit_( leafs ):
        assert(len(leafs) & (len(leafs)-1) == 0), "length must be power of two"
        if len(leafs) == 1:
            return leafs[0]
        else:
            return MerkleTree.H(MerkleTree.commit_(leafs[:len(leafs)//2]) + MerkleTree.commit_(leafs[len(leafs)//2:])).digest()
    
    def open_( index, leafs ):
        assert(len(leafs) & (len(leafs)-1) == 0), "length must be power of two"
        assert(0 <= index and index < len(leafs)), "cannot open invalid index"
        if len(leafs) == 2:
            return [leafs[1 - index]]
        elif index < (len(leafs)/2):
            return MerkleTree.open_(index, leafs[:len(leafs)//2]) + [MerkleTree.commit_(leafs[len(leafs)//2:])]
        else:
            return MerkleTree.open_(index - len(leafs)//2, leafs[len(leafs)//2:]) + [MerkleTree.commit_(leafs[:len(leafs)//2])]
    
    def verify_( root, index, path, leaf ):
        assert(0 <= index and index < (1 << len(path))), "cannot verify invalid index"
        if len(path) == 1:
            if index == 0:
                return root == MerkleTree.H(leaf + path[0]).digest()
            else:
                return root == MerkleTree.H(path[0] + leaf).digest()
        else:
            if index % 2 == 0:
                return MerkleTree.verify_(root, index >> 1, path[1:], MerkleTree.H(leaf + path[0]).digest())
            else:
                return MerkleTree.verify_(root, index >> 1, path[1:], MerkleTree.H(path[0] + leaf).digest())

    def commit( data_array ):
        return MerkleTree.commit_([MerkleTree.H(bytes(da)).digest() for da in data_array])

    def open( index, data_array ):
        return MerkleTree.open_(index, [MerkleTree.H(bytes(da)).digest() for da in data_array])

    def verify( root, index, path, data_element ):
        return MerkleTree.verify_(root, index, path, MerkleTree.H(bytes(data_element)).digest())
