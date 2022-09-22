import matplotlib.pyplot as plt
import csv

good = [0]
bad = [0]

with open("Processed Traffic Data for ML Algorithms/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv") as f:
    # with open("Processed Traffic Data for ML Algorithms/Friday-02-03-2018_TrafficForML_CICFlowMeter_s120000.csv") as f:
    # with open("Processed Traffic Data for ML Algorithms/Friday-02-03-2018_TrafficForML_CICFlowMeter_s22001.csv") as f:
    r = csv.reader(f)

    for line in r:
        if line[-1] == "Benign":
            good.append(good[-1] + 1)
            bad.append(bad[-1])
        else:
            bad.append(bad[-1] + 1)
            good.append(good[-1])


plt.plot(good, color="green", label="good")
plt.plot(bad, color="red", label="bad")
plt.legend()
plt.show()
