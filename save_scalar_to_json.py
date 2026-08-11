import pickle
import json

# Загружаем объект скейлера
with open('scaler.pkl', 'rb') as f:
    scaler = pickle.load(f)

# Определяем, какой тип скейлера и извлекаем параметры
if hasattr(scaler, 'mean_') and hasattr(scaler, 'scale_'):
    # StandardScaler
    params = {
        'type': 'standard',
        'mean': scaler.mean_.tolist(),
        'scale': scaler.scale_.tolist()
    }
elif hasattr(scaler, 'min_') and hasattr(scaler, 'data_range_'):
    # MinMaxScaler
    params = {
        'type': 'minmax',
        'min': scaler.min_.tolist(),
        'max': scaler.data_range_.tolist()   # или scaler.max_ - scaler.min_
    }
else:
    raise ValueError("Неподдерживаемый тип скейлера")

# Сохраняем в JSON
with open('scaler_params.json', 'w') as f:
    json.dump(params, f, indent=2)

print("Параметры скейлера сохранены в scaler_params.json")