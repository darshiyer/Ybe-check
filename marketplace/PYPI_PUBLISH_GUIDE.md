# 🐍 PyPI Publishing Guide - ybe-check v1.0.0

## ✅ Pre-Flight Check (COMPLETED)

```bash
✅ twine installed
✅ Packages validated: PASSED
   - ybe_check-1.0.0-py3-none-any.whl
   - ybe_check-1.0.0.tar.gz
```

---

## 📋 Prerequisites (Do These First)

### 1. Create PyPI Account
- **Production PyPI**: https://pypi.org/account/register/
- **Test PyPI** (optional): https://test.pypi.org/account/register/

### 2. Generate API Token

**For Production PyPI:**
1. Login to https://pypi.org/
2. Go to Account Settings → API tokens
3. Click "Add API token"
4. Name: `ybe-check-v1.0.0`
5. Scope: "Entire account" (first upload) or "Project: ybe-check" (if exists)
6. Copy the token (starts with `pypi-`)

**For Test PyPI (optional):**
- Same steps at https://test.pypi.org/

---

## 🚀 Publishing Commands

### Option 1: Upload to Production PyPI (Recommended)

```bash
# Navigate to project directory
cd /Users/adityaray/Desktop/hackx

# Upload to PyPI
twine upload dist/ybe_check-1.0.0*
```

**You'll be prompted for:**
- **Username:** `__token__` (yes, literally type two underscores, the word token, two underscores)
- **Password:** Paste your API token (e.g., `pypi-AgEIcHlwaS5vcmc...`)

---

### Option 2: Upload to Test PyPI First (Safe Testing)

```bash
# Test upload first
twine upload --repository testpypi dist/ybe_check-1.0.0*
```

**Then test installation:**
```bash
# Create a test virtualenv
python -m venv test_env
source test_env/bin/activate

# Install from Test PyPI
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ ybe-check

# Test it
ybe-check --help
ybe-check scan --help

# Deactivate when done
deactivate
```

**If everything works, upload to production PyPI:**
```bash
twine upload dist/ybe_check-1.0.0*
```

---

## 🔐 Using Environment Variables (Alternative Method)

If you don't want to type credentials each time:

```bash
# Set environment variables
export TWINE_USERNAME=__token__
export TWINE_PASSWORD=pypi-YourActualTokenHere

# Upload (won't prompt for credentials)
twine upload dist/ybe_check-1.0.0*
```

---

## 📦 After Publishing

### Verify Publication
- Check your package: https://pypi.org/project/ybe-check/
- Should show version 1.0.0

### Users Can Install With:
```bash
pip install ybe-check
```

### Commands Available:
```bash
ybe-check scan .
ybe-check report .
ybe-check setup
ybe-check init
ybe-check dashboard
```

---

## 🛠️ Complete Step-by-Step (Copy-Paste Ready)

```bash
# 1. Make sure you're in the right directory
cd /Users/adityaray/Desktop/hackx

# 2. Verify packages are good
twine check dist/ybe_check-1.0.0*
# Should show: PASSED

# 3. Upload to PyPI
twine upload dist/ybe_check-1.0.0*
# Enter __token__ as username
# Paste your API token as password

# 4. Verify it worked
pip install ybe-check --upgrade
ybe-check --help
```

---

## ⚠️ Common Issues & Solutions

### Issue: "File already exists"
**Solution:** You've already uploaded this version. Bump version to 1.0.1 and rebuild.

### Issue: "Invalid credentials"
**Solution:** 
- Make sure username is exactly `__token__` (two underscores before and after)
- Token should start with `pypi-`
- Copy entire token including `pypi-` prefix

### Issue: "403 Forbidden"
**Solution:** 
- First upload needs "Entire account" scope token
- For updates, use "Project: ybe-check" scope token

### Issue: Package description doesn't render properly
**Solution:** 
- Already verified with `twine check` ✅
- Your README.md should render correctly on PyPI

---

## 📊 What Happens After Upload

1. **PyPI processes your package** (usually instant)
2. **Package appears at:** https://pypi.org/project/ybe-check/
3. **Users can install immediately:** `pip install ybe-check`
4. **Package includes:**
   - 16 security scan modules
   - CLI with 5 commands
   - MCP server with 7 tools
   - FastAPI dashboard
   - Full documentation

---

## 🎯 Quick Command Reference

```bash
# Just upload (production)
twine upload dist/ybe_check-1.0.0*

# Upload to test PyPI first
twine upload --repository testpypi dist/ybe_check-1.0.0*

# Upload with explicit credentials
twine upload -u __token__ -p pypi-YOUR_TOKEN dist/ybe_check-1.0.0*

# Reupload if needed (won't work if version exists)
twine upload --skip-existing dist/ybe_check-1.0.0*
```

---

## ✅ Final Checklist Before Publishing

- [x] Twine installed
- [x] Packages validated (PASSED)
- [x] Version 1.0.0 confirmed
- [ ] PyPI account created
- [ ] API token generated
- [ ] Ready to run `twine upload`

**You're ready to publish!** 🚀

When you run the upload command, the package will be live on PyPI within seconds.
