import onnx
from onnx.external_data_helper import convert_model_from_external_data
import torch

# Загружаем модель вместе с внешними данными (файл .data должен лежать рядом)
model = onnx.load("mlp_model.onnx")
model = convert_model_from_external_data(model)
onnx_path = f"mlp_model_best.onnx"
dummy_input = torch.randn(1, 41, device='cpu')
torch.onnx.export(
    model,
    dummy_input,
    onnx_path,
    input_names=['input'],
    output_names=['output'],
    opset_version=13
)