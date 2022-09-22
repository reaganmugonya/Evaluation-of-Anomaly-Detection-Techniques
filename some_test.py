# import numpy as np

# one = np.array([1, 2, 3, 4]).reshape((4, 1))
# two = [1, 5, 30, 4]

# for a, b in zip(one, two):
#     print(a, b)

import csv


def to_int(name):
    return ["ben", "marius"].index(name)


with open("./some.csv") as file:
    csv_iterator = csv.reader(file)

    gesamt_result = []

    for line in csv_iterator:
        category = line[3]
        result = [line[3], line[0], to_int(line[1])]
        print(result)
        gesamt_result.append(result)

    with open("out.csv", "w") as outfile:
        w = csv.writer(outfile)

        for line in gesamt_result:
            w.writerow(line)
