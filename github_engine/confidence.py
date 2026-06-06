def confidence(score):
    if score >= 90:
        return "High"

    elif score >= 60:
        return "Medium"

    return "Low"