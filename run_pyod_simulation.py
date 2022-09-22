import csv
import json
import matplotlib.pyplot as plt
import numpy as np
import sklearn
import time
from tqdm import tqdm

from pyod.models.abod import ABOD
from pyod.models.cblof import CBLOF
from pyod.models.cof import COF
from pyod.models.feature_bagging import FeatureBagging
from pyod.models.hbos import HBOS
from pyod.models.iforest import IForest
from pyod.models.knn import KNN
from pyod.models.lmdd import LMDD
from pyod.models.loda import LODA
from pyod.models.lof import LOF
from pyod.models.loci import LOCI
from pyod.models.lscp import LSCP
from pyod.models.mcd import MCD
from pyod.models.ocsvm import OCSVM
from pyod.models.pca import PCA
from pyod.models.sod import SOD
from pyod.models.sos import SOS
# from pyod.models.combination  # used for combining different estimators
# from pyod.models.auto_encoder import AutoEncoder # needds keras and tensorflow
# from pyod.models.mo_gaal import MO_GAAL # needs tensorflow
# from pyod.models.so_gaal import SO_GAAL # needs tensorflow
# from pyod.models.vae import VAE # needs tensorflow


classifiers = {
    # "ABOD": ABOD,
    # "CBLOF": CBLOF, x fast
    # "COF": COF, # takes ages
    # "FeatureBagging": FeatureBagging,
    "HBOS": HBOS, # x fast
    # "IForest": IForest, x
    # "KNN": KNN,  # ok
    # "LMDD": LMDD, # x
    # "LODA": LODA, x fast
    # "LOF": LOF, # ok
    # "LOCI": LOCI, # x
    # "LSCP": LSCP, # x
    # "MCD": MCD, # x
    # "OCSVM": OCSVM, x
    # "PCA": PCA,  # fastest?
    # "SOD": SOD, # x
    # "SOS": SOS, # x
}


header = ["Duration",
          "Protocol type",
          "Service",
          "Flag",  # this is differnt pos
          "Src_byte",
          "Dst_byte",
          "Land",
          "Wrong_fragment",
          "Urgent",
          "Hot",
          "Num_failed_logins",
          "Logged_in",
          "Num_compromised",
          "Root_shell",
          "Su_attempted",
          "Num_root",
          "Num_file_creations",
          "Num_shells",
          "Num_access_shells",
          "Num_outbound_cmds",
          "Is_hot_login",
          "Is_guest_login",
          "Count",
          "Serror_rate",
          "Rerror_rate",
          "Same_srv_rate",
          "Diff_srv_rate",
          "Srv_count",
          "Srv_serror_rate",
          "Srv_rerror_rate",
          "Srv_diff_host_rate",
          "Dst_host_count",
          "Dst_host_srv_count",
          "Dst_host_same_srv_count",
          "Dst_host_diff_srv_count",
          "Dst_host_same_src_port_rate",
          "Dst_host_srv_diff_host_rate",
          "Dst_host_serror_rate",
          "Dst_host_srv_serror_rate",
          "Dst_host_rerror_rate",
          "Dst_host_srv_rerror_rate",
          "classification",
          "nr of correct classifications out of 21"]

assert(len(header) == 43)

type_to_attack_category = {"back": "dos",
                           "buffer_overflow": "u2r",
                           "ftp_write": "r2l",
                           "guess_passwd": "r2l",
                           "imap": "r2l",
                           "ipsweep": "probe",
                           "land": "dos",
                           "loadmodule": "u2r",
                           "multihop": "r2l",
                           "neptune": "dos",
                           "nmap": "probe",
                           "perl": "u2r",
                           "phf": "r2l",
                           "pod": "dos",
                           "portsweep": "probe",
                           "rootkit": "u2r",
                           "satan": "probe",
                           "smurf": "dos",
                           "spy": "r2l",
                           "teardrop": "dos",
                           "warezclient": "r2l",
                           "warezmaster": "r2l",
                           "normal": "normal"}


def attribute_to_nr(attribute_name: str, value: str) -> int:
    if attribute_name == "protocol_type":
        return ['tcp', 'udp', 'icmp'].index(value)
    elif attribute_name == "service":
        return ['aol', 'auth', 'bgp', 'courier', 'csnet_ns', 'ctf', 'daytime', 'discard', 'domain', 'domain_u', 'echo', 'eco_i', 'ecr_i', 'efs', 'exec', 'finger', 'ftp', 'ftp_data', 'gopher', 'harvest', 'hostnames', 'http', 'http_2784', 'http_443', 'http_8001', 'imap4', 'IRC', 'iso_tsap', 'klogin', 'kshell', 'ldap', 'link', 'login', 'mtp', 'name', 'netbios_dgm', 'netbios_ns', 'netbios_ssn', 'netstat', 'nnsp', 'nntp', 'ntp_u', 'other', 'pm_dump', 'pop_2', 'pop_3', 'printer', 'private', 'red_i', 'remote_job', 'rje', 'shell', 'smtp', 'sql_net', 'ssh', 'sunrpc', 'supdup', 'systat', 'telnet', 'tftp_u', 'tim_i', 'time', 'urh_i', 'urp_i', 'uucp', 'uucp_path', 'vmnet', 'whois', 'X11', 'Z39_50'].index(value)
    elif attribute_name == "flag":
        return ['OTH', 'REJ', 'RSTO', 'RSTOS0', 'RSTR', 'S0', 'S1', 'S2', 'S3', 'SF', 'SH'].index(value)
    else:
        assert(0)


def read_csv_kdd(filename: str, max_nr_rows=-1):
    with open(filename) as kdd:
        reader = csv.reader(kdd)
        data = [line for line in reader]
        results = np.ones(len(data))

        good = 0
        bad = 0
        for i, line in enumerate(data):
            if line[-2] == "normal":
                results[i] = 0.0
                good += 1
            else:
                results[i] = 1.0
                bad += 1

            line[1] = attribute_to_nr("protocol_type", line[1])
            line[2] = attribute_to_nr("service", line[2])
            line[3] = attribute_to_nr("flag", line[3])
            data[i] = np.array(line[:-2], dtype=np.float)

        print("contamination is", bad/(good+bad))
        return np.array(data[:max_nr_rows]), np.array(results[:max_nr_rows])


def read_csv_ids2018(filename: str):
    with open(filename) as ids:
        reader = csv.reader(ids)
        next(reader)  # skip heading
        # data = [line for line in itertools.islice(reader, 2000)]
        data = [line for line in reader]
        results = np.ones(len(data))

        good = 0
        bad = 0
        for i, line in enumerate(data):
            if line[-1] == "Benign":
                results[i] = 0.0
                good += 1
            else:
                results[i] = 1.0
                bad += 1

            # skip date and clock because this won't work out of the box
            line[2:] = line[3:-1]

            data[i] = np.array(line[:-2], dtype=np.float)

            # TODO only use subset of features
            # data[i] = np.array(line[5: 12], dtype=np.float)
            # skip NaN and Infinity
            where_are_NaNs = np.isnan(data[i]) | np.isinf(data[i])
            # give them a specific value ;)
            data[i][where_are_NaNs] = 1.3948284

        print("contamination is", round(bad/(good+bad), 4))
        # return data[:200], results[:200]
        return data, results


def get_stats(actual_arr, should_arr):
    # https://scikit-learn.org/stable/modules/classes.html?highlight=metrics#module-sklearn.metrics
    confusion = sklearn.metrics.confusion_matrix(
        y_true=should_arr, y_pred=actual_arr)
    tn, fp, fn, tp = confusion.ravel()
    # print("TN:", tn, " FP:", fp, " FN:", fn, " TP:", tp)

    f1 = sklearn.metrics.f1_score(
        y_true=should_arr, y_pred=actual_arr)
    # print("F1", f1)

    NORMAL = 0
    ANOMAL = 1
    TP = 0
    TN = 0
    FP = 0
    FN = 0

    P = 0  # anomalies
    N = 0  # normal samples
    for prediction, label in zip(actual_arr, should_arr):
        if label == NORMAL:
            N += 1
        elif label == ANOMAL:
            P += 1
        else:
            assert(0)

        if prediction == label:
            if prediction == NORMAL:
                TN += 1
            elif prediction == ANOMAL:
                TP += 1
            else:
                assert(0)
        else:
            if prediction == NORMAL:
                # label == ANOMAL in this case
                FN += 1
            elif prediction == ANOMAL:
                # label == NORMAL in this case
                FP += 1
    TPR = TP/P
    # assert(TPR == TP/(TP+FN)) # floating point accuracy issue
    TNR = TN/N
    # assert(TNR == TN/(TN + FP)) # floating point accuracy issue
    # PPV = TP/(TP+FP) # sometimes division by zero
    # NPV = TN/(TN+FN)  # sometimes division by zero
    FNR = FN/P
    FPR = FP/N
    # FDR = FP / (FP+TP)  # sometimes division by zero
    # assert(FDR == (1-PPV)) # floating point accuracy issue
    # FOR = FN/(FN+TN)  # sometimes division by zero
    # some skipped from wikipedia, PT, TS
    # ACC = (TP+TN) / (P+N)  # sometimes division by zero
    BA = (TPR+TNR) / 2
    # F1 = (2*TP) / (2*TP+FP+FN)  # sometimes division by zero

    ret = {
        "scipy_stats": {
            "TN:": tn, " FP:": fp, " FN:": fn, " TP:": tp,
            "F1": f1,
        },

        "all_stats": {
            "P": round(P, 2),
            "N": round(N, 2),
            # "TP": round(TP, 2),
            # "TN": round(TN, 2),
            # "FP": round(FP, 2),
            # "FN": round(FN, 2),

            "TPR": round(TPR, 2),
            "TNR": round(TNR, 2),
            # "PPV": round(PPV, 2),
            # "NPV": round(NPV, 2),
            "FNR": round(FNR, 2),
            "FPR": round(FPR, 2),
            # "FDR": round(FDR, 2),
            # "FOR": round(FOR, 2),
            # "ACC": round(ACC, 2),
            "BA": round(BA, 2),
            # "F1": round(F1, 2)
        },
    }

    return ret


def run_simulation(training, evaluations, classifier):
    train_data, train_should_res = training

    # train
    start = time.time()  # time start
    classifier.fit(train_data)

    train_res_is = classifier.predict(train_data)
    training_stats = get_stats(train_res_is, train_should_res)
    train_time = time.time() - start  # time end

    # predict with given outlier percentage
    eval_stats_optimal = []
    for curr_eval in evaluations:
        eval_data, eval_should_res = curr_eval

        start = time.time()  # eval time start
        eval_res_is = classifier.predict(eval_data)
        eval_time = time.time() - start  # eval time end
        eval_stats_optimal.append(
            {"eval_time": eval_time, **
                get_stats(eval_res_is, eval_should_res)}
        )

    # predict for different thresholds for roc curve
    eval_stats_thresholds = []
    NR_OF_POINTS_FOR_ROC_CURVE = 100
    for threshold in np.linspace(0, 1, NR_OF_POINTS_FOR_ROC_CURVE):
        eval_stats_curr = []
        for curr_eval in evaluations:
            eval_data, eval_should_res = curr_eval

            start = time.time()  # eval time start
            eval_res = classifier.predict_proba(np.array(eval_data))
            # apply custom threshold
            # 0 -> normal/ inliers
            eval_res_is = []
            for result in eval_res:
                # result has two elements which added together give 1
                if result[0] < threshold:
                    eval_res_is.append(0)
                else:
                    eval_res_is.append(1)
            eval_time = time.time() - start  # eval time end
            eval_stats_curr.append(
                {"eval_time": eval_time,  **
                    get_stats(eval_res_is, eval_should_res)}
            )

        eval_stats_thresholds.append([threshold, eval_stats_curr])

    return {"training_stats": training_stats,
            "eval_stats_optimal": eval_stats_optimal,
            "eval_stats_thresholds": eval_stats_thresholds,
            "train_time": train_time, }


class NpEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        else:
            return json.JSONEncoder.default(self, obj)


def update_file_with(filename, key, value):
    # create json dumps

    # https: // stackoverflow.com/a/57915246
    # you can open the json dumps in firefox for easier viewing
    with open(filename, "r") as file:
        dictionary = json.load(file)
    dictionary[key] = value

    with open(filename, "w") as file:
        file.write(json.dumps(dictionary, cls=NpEncoder, indent=4))
    print("updated", filename, "at key", key)


training_kdd = read_csv_kdd("./NSL-KDD-Dataset/KDDTrain+.txt")
eval_kdd = read_csv_kdd("./NSL-KDD-Dataset/KDDTest+.txt")


nsl_kdd_res = {}
for name, classifier in tqdm(classifiers.items()):
    res = run_simulation(training=training_kdd, evaluations=[eval_kdd],
                         classifier=classifier(contamination=0.46))
    nsl_kdd_res[name] = res

    update_file_with(filename="nsl_kdd_res.json", key=name, value=res)


# CIC IDS_2018
training_ids_2018 = read_csv_ids2018(
    "Processed Traffic Data for ML Algorithms/Friday-02-03-2018_TrafficForML_CICFlowMeter_s120000.csv")

eval_1_ids_2018 = read_csv_ids2018(
    "Processed Traffic Data for ML Algorithms/Friday-02-03-2018_TrafficForML_CICFlowMeter_s22000.csv")
# eval_2_ids_2018 = read_csv_ids2018(
#     "Processed Traffic Data for ML Algorithms/Friday-02-03-2018_TrafficForML_CICFlowMeter_s22001.csv")
# eval_3_ids_2018 = read_csv_ids2018(
#     "Processed Traffic Data for ML Algorithms/Friday-02-03-2018_TrafficForML_CICFlowMeter_s22002.csv")

# currently don't run multiple evaluations cuase its slow
# ids_evaluation = [eval_1_ids_2018, eval_2_ids_2018, eval_3_ids_2018]
ids_evaluation = [eval_1_ids_2018]

ids_2018_res = {}
for name, classifier in tqdm(classifiers.items()):
    res = run_simulation(training=training_ids_2018, evaluations=ids_evaluation,
                         classifier=classifier(contamination=0.27))
    ids_2018_res[name] = res

    update_file_with(filename="ids_2018_res.json", key=name, value=res)


print("DONE")
