from ecelgamal import ECEG_generate_keys, ECEG_encrypt, ECEG_decrypt, bruteECLog, add, p
from elgamal import EGA_encrypt, EG_decrypt, EG_generate_keys, bruteLog, PARAM_P, PARAM_G
from ecdsa import ECDSA_generate_keys, ECDSA_sign, ECDSA_verify
from dsa import DSA_generate_keys, DSA_sign, DSA_verify, PARAM_P as DSA_P, PARAM_Q as DSA_Q, PARAM_G as DSA_G
import random

class ElectronicVotingSystem:
    def __init__(self, num_voters=10, num_candidates=5, use_ec=True, use_ecdsa=True):
        """
        Initialize the voting system
        Args:
            num_voters: Number of voters (default 10)
            num_candidates: Number of candidates (default 5)
            use_ec: True to use EC ElGamal, False for standard ElGamal
            use_ecdsa: True to use ECDSA, False for DSA
        """
        self.num_voters = num_voters
        self.num_candidates = num_candidates
        self.use_ec = use_ec
        self.use_ecdsa = use_ecdsa
        
        # Generate encryption keys for the voting system
        if use_ec:
            self.priv_key, self.pub_key = ECEG_generate_keys()
        else:
            self.priv_key, self.pub_key = EG_generate_keys(2048, PARAM_P, PARAM_G)
            
        # Generate signature keys for each voter
        self.voter_keys = []
        for _ in range(num_voters):
            if use_ecdsa:
                priv, pub = ECDSA_generate_keys()
            else:
                priv, pub = DSA_generate_keys(2048, DSA_P, DSA_Q, DSA_G)
            self.voter_keys.append((priv, pub))

    def generate_ballot(self, voter_id, candidate_choice):
        """
        Generate an encrypted ballot for a voter's choice
        Args:
            voter_id: ID of the voter (0 to num_voters-1)
            candidate_choice: Chosen candidate (1 to num_candidates)
        Returns:
            tuple: (encrypted_votes, signature)
        """
        if not 1 <= candidate_choice <= self.num_candidates:
            raise ValueError("Invalid candidate choice")
            
        # Create vote list (e.g., [1,0,0,0,0] for candidate 1)
        votes = [1 if i == candidate_choice-1 else 0 for i in range(self.num_candidates)]
        
        # Encrypt each vote
        encrypted_votes = []
        for vote in votes:
            if self.use_ec:
                encrypted_vote = ECEG_encrypt(vote, self.pub_key)
            else:
                encrypted_vote = EGA_encrypt(vote, self.pub_key, PARAM_P, PARAM_G)
            encrypted_votes.append(encrypted_vote)
            
        # Sign the encrypted ballot
        message = str(encrypted_votes).encode()
        if self.use_ecdsa:
            signature = ECDSA_sign(message, self.voter_keys[voter_id][0])
        else:
            signature = DSA_sign(message, self.voter_keys[voter_id][0], DSA_P, DSA_Q, DSA_G)
            
        return encrypted_votes, signature

    def verify_ballot(self, voter_id, encrypted_votes, signature):
        """
        Verify the signature on a ballot
        """
        message = str(encrypted_votes).encode()
        if self.use_ecdsa:
            return ECDSA_verify(message, signature[0], signature[1], 
                              self.voter_keys[voter_id][1])
        else:
            return DSA_verify(message, signature[0], signature[1], 
                            self.voter_keys[voter_id][1], DSA_P, DSA_Q, DSA_G)

    def tally_votes(self, all_encrypted_votes):
        """
        Tally all votes using homomorphic properties
        Args:
            all_encrypted_votes: List of lists of encrypted votes
        Returns:
            list: Vote counts for each candidate
        """
        # Initialize sum for each candidate position
        sums = []
        for i in range(self.num_candidates):
            if self.use_ec:
                # Start with "zero" point for EC
                sum_c1, sum_c2 = (1, 0), (1, 0)
            else:
                # Start with multiplicative identity for standard ElGamal
                sum_c1, sum_c2 = 1, 1
                
            # Add/multiply all votes for this candidate position
            for ballot in all_encrypted_votes:
                c1, c2 = ballot[i]
                if self.use_ec:
                    # EC addition
                    sum_c1 = add(sum_c1[0], sum_c1[1], c1[0], c1[1], p)
                    sum_c2 = add(sum_c2[0], sum_c2[1], c2[0], c2[1], p)
                else:
                    # Multiplicative homomorphism
                    sum_c1 = (sum_c1 * c1) % PARAM_P
                    sum_c2 = (sum_c2 * c2) % PARAM_P
            
            sums.append((sum_c1, sum_c2))
        
        # Decrypt and convert to actual vote counts
        results = []
        for sum_vote in sums:
            if self.use_ec:
                decrypted = ECEG_decrypt(sum_vote, self.priv_key)
                count = bruteECLog(decrypted[0], decrypted[1], p)
            else:
                decrypted = EG_decrypt(sum_vote[0], sum_vote[1], self.priv_key, PARAM_P, PARAM_G)
                count = bruteLog(PARAM_G, decrypted, PARAM_P)
            results.append(count)
            
        return results

# Example usage
def test_voting_system():
    # Initialize system with EC ElGamal and ECDSA
    evs = ElectronicVotingSystem(num_voters=10, num_candidates=5, use_ec=True, use_ecdsa=True)
    
    # Simulate voting
    all_encrypted_votes = []
    for voter_id in range(10):
        # Each voter chooses a random candidate
        candidate = random.randint(1, 5)
        encrypted_votes, signature = evs.generate_ballot(voter_id, candidate)
        
        # Verify the ballot
        if evs.verify_ballot(voter_id, encrypted_votes, signature):
            all_encrypted_votes.append(encrypted_votes)
        else:
            print(f"Invalid ballot from voter {voter_id}")
    
    # Tally the votes
    results = evs.tally_votes(all_encrypted_votes)
    
    # Print results
    for i, count in enumerate(results, 1):
        print(f"Candidate {i}: {count} votes")

if __name__ == "__main__":
    test_voting_system()
