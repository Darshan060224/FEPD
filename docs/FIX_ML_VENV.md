# 🔧 FIX: ML Libraries Not Available

## ⚠️ Issue
```
WARNING - ML libraries not available. Install: pip install scikit-learn tensorflow
```

## ✅ Solution: Always Use Virtual Environment

### Option 1: VS Code (Recommended) ⭐

**The settings have been updated!** Now when you run FEPD:

1. **Press F5** or click "Run and Debug" (▶️)
2. Select: **"FEPD - Main Application"**
3. ✅ It will automatically use the venv with ML libraries!

### Option 2: Use the Launcher Script

Double-click or run:
```batch
run_fepd.bat
```

This automatically activates venv and runs FEPD.

### Option 3: Terminal (Manual)

```batch
# 1. Activate venv
.venv\Scripts\activate

# 2. Run FEPD
python main.py
```

## 🔍 How to Verify

After launching FEPD, you should see:
```
✓ ML anomaly detection running
✓ UEBA profiling working
✓ NO "ML libraries not available" warnings
```

## ❌ Common Mistakes

**DON'T:**
- Click the Python file and "Run Python File" without venv
- Run `python main.py` from a non-activated terminal
- Use system Python instead of venv Python

**DO:**
- Use F5 in VS Code (now configured correctly)
- Use `run_fepd.bat`
- Activate venv first, then run

## 🎯 Quick Test

1. **In VS Code**: Press `F5` → Select "Test ML Integration"
2. Should see:
   ```
   ✓ scikit-learn
   ✓ tensorflow 2.20.0
   ✓ Running in virtual environment
   ✓ ML_AVAILABLE = True
   ```

## 📝 What Changed

Updated `.vscode/settings.json`:
```json
{
    "python.defaultInterpreterPath": "${workspaceFolder}/.venv/Scripts/python.exe",
    "python.terminal.activateEnvironment": true
}
```

Created `.vscode/launch.json`:
- ✅ FEPD - Main Application
- ✅ ML Training configurations
- ✅ All use venv Python

## ✨ Result

**FEPD will now always have ML capabilities when launched from VS Code!** 🚀
