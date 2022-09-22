import sys
import numpy as np
from numpy.core.fromnumeric import cumproduct

filename = sys.argv[1]
print("input file is:", filename)


def save_file_with_size(filename: str, size: int, content):
    new_filename = filename[:-4] + "_s" + str(size) + ".csv"
    print("SAVING size", size, "to file", new_filename)

    with open(new_filename, "w") as output:
        for line in content:
            output.write(line)


with open(filename) as input_iterator:
    next(input_iterator)  # skip header
    content = []

    for line in input_iterator:
        content.append(line)

    np.random.shuffle(content)

    for size in sys.argv[2:]:
        print("split file into", size)

        size = int(size)
        curr_content = content[:size]
        save_file_with_size(filename, size, curr_content)
        content = curr_content
