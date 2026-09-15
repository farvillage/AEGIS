import time
import psutil
import os
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support

class AegisBenchmarkCollector:
    def __init__(self):
        self.process = psutil.Process(os.getpid())
        self.reset_metrics()

    def reset_metrics(self):
        self.latencies = []
        self.cpu_usages = []
        self.memory_usages = []

    def start_measurement(self):
        self.start_time = time.perf_counter()
        self.start_cpu = self.process.cpu_percent(interval=None)
        self.start_mem = self.process.memory_info().rss / (1024 * 1024) # MB

    def stop_measurement(self):
        end_time = time.perf_counter()
        latency_ms = (end_time - self.start_time) * 1000
        current_mem = self.process.memory_info().rss / (1024 * 1024)
        
        self.latencies.append(latency_ms)
        self.memory_usages.append(current_mem)
        return latency_ms

    def calculate_security_metrics(self, y_true, y_pred):
        cm = confusion_matrix(y_true, y_pred)
        tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
        
        tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0 # Sensibilidade / Recall
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0 # Taxa de Falso Positivo
        
        precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, average='binary', zero_division=0)
        
        return {
            "Confusion_Matrix": {"TN": int(tn), "FP": int(fp), "FN": int(fn), "TP": int(tp)},
            "TPR": float(tpr),
            "FPR": float(fpr),
            "Precision": float(precision),
            "Recall": float(recall),
            "F1_Score": float(f1),
            "Mean_Latency_ms": float(sum(self.latencies) / len(self.latencies)) if self.latencies else 0.0,
            "Mean_Memory_MB": float(sum(self.memory_usages) / len(self.memory_usages)) if self.memory_usages else 0.0
        }