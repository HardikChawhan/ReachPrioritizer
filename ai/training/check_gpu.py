"""Quick check that PyTorch can see your NVIDIA GPU before starting training."""
import sys

try:
    import torch
except ImportError:
    sys.exit("PyTorch is not installed. See docs/AI_MODEL_AND_TRAINING.md (step 2).")

print(f"PyTorch {torch.__version__} | CUDA build: {torch.version.cuda}")
if not torch.cuda.is_available():
    sys.exit("CUDA is NOT available -> you installed the CPU-only PyTorch, or the NVIDIA driver is missing/old.\n"
             "Reinstall with: pip install --force-reinstall torch --index-url https://download.pytorch.org/whl/cu128")
name = torch.cuda.get_device_name(0)
cap = torch.cuda.get_device_capability(0)
mem = torch.cuda.get_device_properties(0).total_memory / 1024 ** 3
print(f"GPU: {name} | compute capability {cap[0]}.{cap[1]} | {mem:.1f} GB VRAM | bf16: {torch.cuda.is_bf16_supported()}")
x = torch.randn(2048, 2048, device="cuda")
torch.cuda.synchronize()
print("Matrix multiply on GPU OK:", float((x @ x).sum()) is not None)
if mem < 7.5:
    print("Tip: use --batch-size 8 --grad-accum 4 on GPUs with less than 8 GB VRAM.")
print("Ready to train: python ai/training/train_codebert.py")
