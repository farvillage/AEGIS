import numpy as np

def calculate_grc_risk_score(attack_count, total_rows):
    """
    Calculates quantitative GRC risk score based on intrusion ratio and CIA impact weighting.
    """
    if total_rows == 0:
        return 0.0, "Low"
    
    intrusion_probability = attack_count / total_rows
    
    # CIA Triad Weights & Impact Scale (1-5) for Critical IoMT
    weights = {"C": 0.4, "I": 0.4, "A": 0.2}
    impacts = {"C": 5, "I": 5, "A": 4} 
    weighted_impact = (weights["C"] * impacts["C"] + 
                       weights["I"] * impacts["I"] + 
                       weights["A"] * impacts["A"])
    
    risk_score = intrusion_probability * weighted_impact * 100 # Scaled to percentage
    
    if risk_score > 50:
        level = "Critical"
    elif risk_score > 20:
        level = "High"
    elif risk_score > 5:
        level = "Medium"
    else:
        level = "Low"
        
    return round(risk_score, 2), level