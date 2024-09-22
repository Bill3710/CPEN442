import copy
import random
import ngram_score as ns

# Question 6.1 #
group25_cipherText = 'SMLKGOHVILKQMDOECGTSAUEZKQKYPOEKOVWUOMWCXWILMCXRMWLKLOWGOVKLGLVOMCGOOPDGDLPLFRHCLVWGOBNTMTUCOTSOHYEPNZMTXODLRVTSYUEDHVGFXBPEEQSNTZWQRSZKELODCNSMZKEZSNTEXLSZWXOVWGWQYTLGLDVNFETELKRDDWKGYPXOTKLOWGYMHZTSILTIDLHCLVCMUYOBYVPEGDOVWGTZQVKIMDOESNSMKTHXMSWGOGBAEKVOMTLGLOFNFWOXGLDGEPOKSMDKPOFXLDSKNHSKXRVTKFBU'

keyChars = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']

def generate_random_matrix():
    # Create a shuffled copy of keyChars
    random_key = random.sample(keyChars, len(keyChars))
    matrix = []
    for char in random_key:
        if char not in matrix:
            matrix.append(char)
    
    # Reshaping into a 5x5 matrix
    return [matrix[i:i+5] for i in range(0, len(matrix), 5)]

def find_char_in_matrix(matrix, char):
     for row in range(len(matrix)):
        for col in range(len(matrix[0])):
            if matrix[row][col] == char:
                return (row, col)

def decrypt_playfair_with_key(ciphertext, key_matrix):
    plaintext = ""

    char_pairs = [ciphertext[i:i+2] for i in range(0, len(ciphertext), 2)]

    for char_pair in char_pairs:
        # Get position of the two chars
        (row1, col1) = find_char_in_matrix(key_matrix, char_pair[0])
        (row2, col2) = find_char_in_matrix(key_matrix, char_pair[1])
        
        if row1 == row2:
            # same row, shift left
            plaintext += key_matrix[row1][(col1-1)%5] + key_matrix[row2][(col2-1)%5]
        elif col1 == col2:
            # same col, shift up
            plaintext += key_matrix[(row1-1)%5][col1] + key_matrix[(row2-1)%5][col2]
        else:
            # rectangle, switch col
            plaintext += key_matrix[row1][col2] + key_matrix[row2][col1]

    return plaintext

# From: http://practicalcryptography.com/cryptanalysis/text-characterisation/quadgrams/
fitness = ns.ngram_score('english_quadgrams.txt')

# number of iterations to run the Genetic Algorithms
iterations = 1000000


parent_matrix = generate_random_matrix()
best_key_matrix = parent_matrix
parent_score = fitness.score(decrypt_playfair_with_key(group25_cipherText, parent_matrix))
max_score = parent_score

for i in range (0, iterations):
    # generate a random number for action decision
    random_number = random.randint(1, 100)

    child_matrix = copy.deepcopy(parent_matrix)

    # dicision making
    '''
    if random_number == 1:
        # 1% reset the whole matrix randomly
        child_matrix = generate_random_matrix()
    '''
    
    if random_number <= 90 :
        # 75%: just swap two position randomly
        row1 = random.randint(0, 4)
        col1 = random.randint(0, 4)
        row2 = random.randint(0, 4)
        col2 = random.randint(0, 4)
  
        temp = child_matrix[row1][col1]
        child_matrix[row1][col1] = child_matrix[row2][col2]
        child_matrix[row2][col2] = temp
    elif random_number <= 92 :
        # 5% flip matrix across NW-SE axis
        child_matrix = [list(reversed(row)) for row in reversed(child_matrix)]
    elif random_number <= 94 :
        # 5%: swap two rows
        row1 = random.randint(0, 4)
        row2 = random.randint(0, 4)

        temp = child_matrix[row1]
        child_matrix[row1] = child_matrix[row2]
        child_matrix[row2] = temp
    elif random_number <= 96 :
        # 5%: swap two cols
        col1 = random.randint(0, 4)
        col2 = random.randint(0, 4)

        for i in range(len(child_matrix)):
            temp = child_matrix[i][col1]
            child_matrix[i][col1] = child_matrix[i][col2]
            child_matrix[i][col2] = temp
    elif random_number <= 98 :
        # 5%: flip vertically
        child_matrix = child_matrix[::-1]
    else :
        # 5%: flip horizontally
        for row in child_matrix:
            row.reverse()

    cur_score = fitness.score(decrypt_playfair_with_key(group25_cipherText, child_matrix))

    if cur_score > parent_score:
        # when improvement, heritage the advantage
        parent_matrix = child_matrix
        parent_score = cur_score

    # keep track of the best reselt 
    if cur_score > max_score:
        max_score = cur_score
        best_key_matrix = child_matrix


# now we have the best key print the key, its score, and plaintext

for row in best_key_matrix:
    print(row)

print(max_score)

print(decrypt_playfair_with_key(group25_cipherText, best_key_matrix))

print('done')