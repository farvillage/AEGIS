import numpy as np
import onnxruntime as ort
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

def optimize_and_export_model(sklearn_model, num_features):
    # Define input tensor type for the ONNX graph based on feature dimensions
    initial_type = [('float_input', FloatTensorType([None, num_features]))]
    model_onnx = convert_sklearn(sklearn_model, initial_types=initial_type)
    
    # Convert scikit-learn model to ONNX using skl2onnx
    with open("models/aegis_ciciomt_model.onnx", "wb") as f:
        f.write(model_onnx.SerializeToString())

class OptimizedAegisInference:
    def __init__(self, model_path="models/aegis_ciciomt_model.onnx"):  # Updated here
        # Configure ONNX Runtime for low-latency edge inference
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = 2
        opts.inter_op_num_threads = 1
        opts.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
        
        self.session = ort.InferenceSession(model_path, opts, providers=['CPUExecutionProvider'])
        self.input_name = self.session.get_inputs()[0].name
        self.output_name = self.session.get_outputs()[0].name

    def predict(self, features_df):
        # Format input data for the ONNX runtime session
        input_data = features_df.select_dtypes(include=[np.number]).fillna(0).to_numpy(dtype=np.float32)
        
        # Run sub-millisecond edge inference
        outputs = self.session.run([self.output_name], {self.input_name: input_data})
        predictions = outputs[0]
        
        attack_count = int(np.sum(predictions))
        return features_df, attack_count