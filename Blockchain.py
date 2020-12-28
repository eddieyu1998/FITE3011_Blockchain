import time
from hashlib import sha256
from collections import OrderedDict
from collections.abc import Iterable

TEST_CASE = [["Alice -> Bob: 10"],
             ["Alice -> Bob: 1", "Charlie -> Dan: 6", "Dan -> Bob: 2"],
             ["Bob -> Alice: 4", "Elle -> Alice: 9"],
             ["Bob -> Alice: 5", "Elle -> Alice: 3"]]
LEFT, RIGHT, UNKNOWN = ('Left', 'Right', 'Unknown')

# function for hashing one or more strings using sha256
# strings are encoded using utf-8 before hashing
def hashStrings(*strings):
    sequence = ""
    for string in strings:
        sequence += string
    return sha256(sequence.encode('utf-8')).hexdigest()

# function for hashing one or more hexadecimal strings using sha256
# hexadecimal strings are transformed back to bytes before hashing
def hashHexdigests(*hexdigests):
    sequence = b''
    for hexdigest in hexdigests:
        sequence += bytes.fromhex(hexdigest)
    return sha256(sequence).hexdigest()

# format of the path of merkle proof: [(nodeHash, nodeOrientation), (nodeHash, nodeOrientation), ...]
def calculateMerkleRoot(transaction, path):
    digest = hashStrings(transaction)
    for node in path:
        nodeHash = node[0]
        orientation = node[1]
        if orientation == LEFT:  # node is on the left
            digest = hashHexdigests(nodeHash, digest)
        elif orientation == RIGHT:  # node is on the right
            digest = hashHexdigests(digest, nodeHash)
    return digest
    #if digest == merkleTreeRoot:
        #return True
    #else:
        #return False
        
class MerkleNode:
    def __init__(self, nodeHash, left=None, right=None, transaction=None):
        self.hash = nodeHash
        self.left = left
        self.right = right
        self.transaction=transaction
        self.parent = None
        if (left and right):
            left._setParent(self)
            right._setParent(self)
            left._setSibling(right)
            right._setSibling(left)
    
    def _setParent(self, parent):
        self.parent = parent
    
    def _setSibling(self, sibling):
        self.sibling = sibling
    
    def duplicateSelf(self):
        return MerkleNode(self.hash)
    
    def getOrientation(self):
        if not self.parent:
            return UNKNOWN
        else:
            if self.parent.left is self:
                return LEFT
            elif self.parent.right is self:
                return RIGHT
            else:
                return UNKNOWN
            
class MerkleTree:
    def __init__(self, transactions=[]):
        self.leaves = OrderedDict()
        self.root = None
        self._buildTree(transactions)

    def _buildTree(self, transactions):
        if not transactions:
            return
        nodes = [MerkleNode(hashStrings(transaction), transaction=transaction) for transaction in transactions]
        for node in nodes:
            self.leaves[node.hash] = node
        while len(nodes) > 1:
            if len(nodes) % 2 != 0:
                nodes.append(nodes[-1].duplicateSelf())
            nodes = [MerkleNode(hashHexdigests(l.hash,r.hash), l, r) for l, r in zip(nodes[0::2], nodes[1::2])]
        self.root = nodes[0]
        
    def getRoot(self):
        if not self.root:
            return None
        return self.root.hash
    
    def getTransactions(self):
        return [node.transaction for key, node in self.leaves.items()]
    
    def getProof(self, transaction):
        transactionHash = hashStrings(transaction)
        if transactionHash not in self.leaves:
            return (False, [])
        else:
            node = self.leaves[transactionHash]
            proofs = []
            while node != self.root:
                proofs.append((node.sibling.hash, node.sibling.getOrientation()))
                node = node.parent
            return (True, proofs)
            
    def getTreeContent(self):
        def getLayers(node, layer):
            layers = "|   "*(layer-1)+"|-- "*(layer>0)+node.hash+"\n"
            if not (node.left or node.right):
                return layers
            layers += getLayers(node.left, layer+1)
            layers += getLayers(node.right, layer+1)
            return layers
        content = getLayers(self.root, 0)
        return content
        
    def printTree(self):
        tree = self.getTreeContent()
        print(tree)

class BlockHeader:
    def __init__(self, previousBlockHeaderHash, merkleTreeRoot, timestamp, nonce):
        self.previousBlockHeaderHash = previousBlockHeaderHash
        self.merkleTreeRoot = merkleTreeRoot
        self.timestamp = timestamp
        self.nonce = nonce
        
class Block:
    def __init__(self, transactions, previousBlockHeaderHash, difficulty):
        self.merkleTree = MerkleTree(transactions)
        merkleTreeRoot = self.merkleTree.getRoot()
        timestamp = int(time.time())
        nonce = self._findNonce(previousBlockHeaderHash, merkleTreeRoot, timestamp, difficulty)
        self.header = BlockHeader(previousBlockHeaderHash, merkleTreeRoot, timestamp, nonce)
        
    def _findNonce(self, previousBlockHeaderHash, merkleTreeRoot, timestamp, difficulty):
        target = 2 ** (256 - difficulty)
        previousHashBytes = bytes.fromhex(previousBlockHeaderHash)
        rootBytes = bytes.fromhex(merkleTreeRoot)
        timeBytes = timestamp.to_bytes(4, 'big')
        # retry? no?
        for i in range(2 ** 32):
            nonceBytes = i.to_bytes(4, 'big')
            blockHash = sha256(previousHashBytes+rootBytes+timeBytes+nonceBytes)
            if int.from_bytes(blockHash.digest(), 'big') < target:
                self.hash = blockHash.hexdigest()
                return nonceBytes.hex()
            
    def getTransactions(self):
        return self.merkleTree.getTransactions()

class Blockchain:
    def __init__(self, difficulty=8):
        self.blocks = []
        self.mempool = []
        self.difficulty = difficulty
        
    def start(self):
        self.printBlockchain()
        self.repl()
            
    def repl(self):
        self.printMempool()
        userInput = input("Add new transactions, or Enter empty string to make new block: ")
        while True:
            if not userInput.strip(" "):
                self.makeBlock()
                self.printBlockchain()
            else:
                self.addTransaction(userInput)
                self.printMempool()
            userInput = input("Add new transactions, or Enter empty string to make new block: ")
    
    def getPreviousBlockHash(self):
        if not self.blocks:
            return (0).to_bytes(32, 'big').hex()
        else:
            return self.blocks[-1].hash
                
    def getTransactions(self):
        if not self.blocks:
            return []
        return self.blocks[-1].getTransactions()
        
    def addTransaction(self, transaction):
        if isinstance(transaction, str):
            self.mempool.append(transaction)
        elif isinstance(transaction, Iterable):
            self.mempool.extend(transaction)
        
    def makeBlock(self):
        if not self.mempool:
            print("There is no transactions in mempool")
            return
        block = Block(self.getTransactions()+self.mempool, self.getPreviousBlockHash(), self.difficulty)
        self.blocks.append(block)
        self.mempool = []
        
    def getMerkleRoot(self):
        if not self.blocks:
            return None
        else:
            return self.blocks[-1].merkleTree.getRoot()
        
    def getMerkleProof(self, transaction):
        if not self.blocks:
            return (False, [])
        return self.blocks[-1].merkleTree.getProof(transaction)
    
    def getProofPathContent(self, transaction):
        proof = self.getMerkleProof(transaction)
        inBlockchain = proof[0]
        content = ""
        if not inBlockchain:
            content = "{}: Transaction not in blockchain\n".format(transaction)
        else:
            path = proof[1]
            content += "Merkle proof path for transaction: {}\n".format(transaction)
            for node in path:
                content += "{} {}\n".format(node[1], node[0])
        return content
    
    def printProofPath(self, transaction):
        print(self.getProofPathContent(transaction))
                
    def printProofPathToFile(self, transaction, filename="merkle-proof.txt"):
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(self.getProofPathContent(transaction))
        
    def printMempool(self):
        print("Current mempool:")
        for transaction in self.mempool:
            print("    {}".format(transaction))
        print()
        
    def getBlockchainContent(self):
        content = ""
        for index, block in enumerate(self.blocks):
            content += "Block number {}:\n".format(index)
            content += "Block hash: {}\n".format(block.hash)
            content += "Block header:\n"
            content += "|-- Previous block header hash: {}\n".format(block.header.previousBlockHeaderHash)
            content += "|-- Merkle tree root: {}\n". format(block.header.merkleTreeRoot)
            content += "|-- Timestamp: {}\n".format(block.header.timestamp)
            content += "|-- Nonce: {}\n".format(block.header.nonce)
            content += "Transactions:\n"
            for transaction in block.getTransactions():
                content += "|-- {} ({})\n".format(transaction, hashStrings(transaction))
            content += "MerkleTree:\n"
            content += block.merkleTree.getTreeContent() + "\n"
        return content
        
    def printBlockchain(self):
        if not self.blocks:
            print("There is currently no data in blockchain")
        else:
            print(self.getBlockchainContent())
                
    def printBlockchainToFile(self, filename="blockchain-content.txt"):
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(self.getBlockchainContent())

class TestBlockchain:
    def __init__(self, difficulty=8):
        self.blockchain = Blockchain(difficulty)
        self.timestampedTransactions = []
        
    def runTestCase(self, testCase, output="blockchain-content.txt"):
        timestampedTransactions = []
        print("Transactions made:")
        for blockNumber, block in enumerate(testCase):
            blockTransactions = ["{} {}".format(str(int(time.time())), transaction) for transaction in block]
            timestampedTransactions.append(blockTransactions)
            self.blockchain.addTransaction(blockTransactions)
            self.blockchain.makeBlock()
            print("Block {}:".format(blockNumber+len(self.timestampedTransactions)))
            [print("|-- {}".format(transaction)) for transaction in blockTransactions]
            time.sleep(1)
        self.timestampedTransactions += timestampedTransactions
        print("Writing timestamped transactions to file...")
        with open("timestamped-transactions.txt", 'w', encoding='utf-8') as f:
            for blockNumber, block in enumerate(self.timestampedTransactions):
                f.write("Block {}:\n".format(blockNumber))
                [f.write("|-- {}\n".format(transaction)) for transaction in block]
        print("Timestamped transactions written to file: {}\n".format("timestamped-transactions.txt"))
        
        self.blockchain.printBlockchain()
        print("Writing Blockchain content to file...")
        self.blockchain.printBlockchainToFile(output)
        print("Blockchain content written to file: {}\n".format(output))
        
    def testMerkleProof(self, transaction, output="merkle-proof.txt"):
        print("Running merkle proof test for transaction: {}\n".format(transaction))
        content = "transaction: {}\n".format(transaction)
        content += "transaction hash: {}\n".format(hashStrings(transaction))
        merkleRoot = self.blockchain.getMerkleRoot()
        content += "merkleRoot: {}\n\n".format(merkleRoot)
        proof = self.blockchain.getMerkleProof(transaction)
        merkleProofPathContent = self.blockchain.getProofPathContent(transaction)
        content += merkleProofPathContent
        calculatedMerkleRoot = calculateMerkleRoot(transaction, proof[1])
        content += "\nCalculated merkle root: {}".format(calculatedMerkleRoot)
        
        print(content)
        print("Writing MerkleProof to file...")
        with open(output, 'w', encoding='utf-8') as f:
            f.write(content)
        print("Merkle proof written to file: {}\n".format(output))
    
    def reset(self, difficulty=8):
        self.blockchain = Blockchain(difficulty)
        self.timestampedTransactions = []
        
if __name__ == "__main__":
    print("Starting blockchain...")
    blockchain = Blockchain()
    blockchain.start()