import numpy as np
import onnxruntime as ort
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

def optimize_and_export_model(sklearn_model, num_features):
    """
    Optimizes and exports a scikit-learn model to ONNX format.
    """
    initial_type = [('float_input', FloatTensorType([None, num_features]))]
    model_onnx = convert_sklearn(sklearn_model, initial_types=initial_type)
    
    with open("models/aegis_ciciomt_model.onnx", "wb") as f:
        f.write(model_onnx.SerializeToString())

class OptimizedAegisEnsembleInference:
    """
    Advanced Weighted Ensemble Inference Engine (Random Forest + XGBoost) 
    powered by ONNX Runtime for ultra-low latency edge/MEC environments.
    """
    def __init__(self, rf_model_path="models/aegis_ciciomt_model.onnx", 
                 xgb_model_path="models/aegis_ciciomt_xgboost.onnx",
                 weight_rf=0.5, weight_xgb=0.5):
        
        # Store ensemble weights (must sum to 1.0)
        self.weight_rf = weight_rf
        self.weight_xgb = weight_xgb
        
        # Configure ONNX Runtime session options
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = 2
        opts.inter_op_num_threads = 1
        opts.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
        
        # Initialize Random Forest ONNX session
        self.rf_session = ort.InferenceSession(rf_model_path, opts, providers=['CPUExecutionProvider'])
        self.rf_input_name = self.rf_session.get_inputs()[0].name
        self.rf_output_name = self.rf_session.get_outputs()[0].name
        
        # Initialize XGBoost ONNX session (with graceful fallback if model file isn't generated yet)
        try:
            self.xgb_session = ort.InferenceSession(xgb_model_path, opts, providers=['CPUExecutionProvider'])
            self.xgb_input_name = self.xgb_session.get_inputs()[0].name
            self.xgb_output_name = self.xgb_session.get_outputs()[0].name
            self.has_xgb = True
        except Exception:
            self.has_xgb = False

    def predict(self, features_df):
        """
        Executes preprocessing, extracts the 8 core features, and runs 
        weighted ensemble probability combination across available ONNX models.
        """
        # Isolate the first 8 numeric features required by the ONNX graphs
        numeric_df = features_df.select_dtypes(include=[np.number])
        inference_df = numeric_df.iloc[:, :8].fillna(0)
        input_data = inference_df.to_numpy(dtype=np.float32)
        
        # Run Random Forest ONNX inference
        rf_outputs = self.rf_session.run([self.rf_output_name], {self.rf_input_name: input_data})
        rf_preds = rf_outputs[0]
        
        # If XGBoost ONNX session is active, compute weighted ensemble
        if self.has_xgb:
            xgb_outputs = self.xgb_session.run([self.xgb_output_name], {self.xgb_input_name: input_data})
            xgb_preds = xgb_outputs[0]
            
            # Combine predictions via weighted average (or probability blending)
            # Assuming binary output indicators (0 or 1)
            ensemble_score = (self.weight_rf * rf_preds) + (self.weight_xgb * xgb_preds)
            predictions = (ensemble_score >= 0.5).astype(int)
        else:
            predictions = rf_preds
        
        attack_count = int(np.sum(predictions))
        return features_df, attack_count