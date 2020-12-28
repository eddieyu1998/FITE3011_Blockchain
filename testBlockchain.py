import Blockchain

TEST_CASE = [["Alice -> Bob: 10"],
             ["Alice -> Bob: 1", "Charlie -> Dan: 6", "Dan -> Bob: 2"],
             ["Bob -> Alice: 4", "Elle -> Alice: 9"],
             ["Bob -> Alice: 5", "Elle -> Alice: 3"]]

if __name__ == "__main__":
    tester = Blockchain.TestBlockchain()
    tester.runTestCase(TEST_CASE)
    tester.testMerkleProof(tester.timestampedTransactions[2][0], "merkle-proof1.txt")
    tester.testMerkleProof(tester.timestampedTransactions[3][1], "merkle-proof2.txt")