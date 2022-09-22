import json
import matplotlib.pyplot as plt

# plot roc curve for a dataset and the evaluated techniques
with open("nsl_kdd_res.json", "r") as file:
    dictionary = json.load(file)

for techniqe, stats in dictionary.items():
    FPRates = []
    TPRates = []

    curr_res = stats["eval_stats_thresholds"]
    # iterate trhough all the thresholds
    print("Plotting for Technique", techniqe)
    for simulation_with_threshold in curr_res:
        threshold = simulation_with_threshold[0]
        eval_stats = simulation_with_threshold[1]
        # we only look at the first evaluation sample, there may be multile which coul be avaeraged or stuff
        # eval_stats_curr = eval_stats_curr[0]
        # print(eval_stats)
        eval_stats = eval_stats[0]
        print(eval_stats)
        FPRates.append(1 - eval_stats["all_stats"]["FPR"])
        TPRates.append(1 - eval_stats["all_stats"]["TPR"])
    print(FPRates)
    print(TPRates)
    # TODO sort the points and then plot the line.. but the resolution needs to be higher
    data = [[x, y] for x, y in zip(FPRates, TPRates)]
    data.sort(key=lambda coordiante: coordiante[0])  # sort based on x
    plt.plot([cord[0] for cord in data],
             [cord[1] for cord in data], label=techniqe)

plt.xlabel("FPR")
plt.ylabel("TPR")
plt.legend()
plt.show()
