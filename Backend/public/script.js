// ✅ AUTO-DETECT API URL (Live Server + Express)
const getApiUrl = () => {
  if (window.location.port === '5000') return '/api/auth';
  return 'http://localhost:5000/api/auth';
};

axios.defaults.baseURL = getApiUrl();
axios.defaults.headers.post['Content-Type'] = 'application/json';
let currentToken = localStorage.getItem('token');
let currentEmail = '';

function showPage(pageId) {
  document.querySelectorAll('[id$="-page"]').forEach(p => p.classList.add('d-none'));
  document.getElementById(pageId).classList.remove('d-none');
}

// Token interceptor
axios.interceptors.request.use(config => {
  currentToken = localStorage.getItem('token');
  if (currentToken) config.headers.Authorization = `Bearer ${currentToken}`;
  return config;
});

// Page load check
window.addEventListener('load', async () => {
  if (currentToken) {
    try {
      await loadDashboard();
      showPage('dashboard-page');
    } catch {
      localStorage.removeItem('token');
      showPage('login-page');
    }
  } else {
    showPage('login-page');
  }
});

// Login
document.getElementById('login-form').addEventListener('submit', async e => {
  e.preventDefault();
  const email = document.getElementById('email').value.trim().toLowerCase();
  const password = document.getElementById('password').value;
  const msgEl = document.getElementById('login-msg');
  
  msgEl.innerHTML = '<div class="alert alert-info">Logging in...</div>';
  
  try {
    const { data } = await axios.post('/login', { email, password });
    localStorage.setItem('token', data.token);
    msgEl.innerHTML = '<div class="alert alert-success">Login successful! Redirecting...</div>';
    setTimeout(() => { showPage('dashboard-page'); loadDashboard(); }, 1500);
  } catch (err) {
    msgEl.innerHTML = `<div class="alert alert-danger">${err.response?.data?.msg || 'Login failed'}</div>`;
  }
});

// ✅ FIXED OTP Flow - No validation errors
document.getElementById('forgot-form').addEventListener('submit', async e => {
  e.preventDefault();
  const emailStep = document.getElementById('emailStep');
  const otpStep = document.getElementById('otpStep');
  const passwordStep = document.getElementById('passwordStep');
  
  // Step 1: Send OTP
  if (!emailStep.classList.contains('d-none')) {
    const email = document.getElementById('forgot-email').value.trim();
    if (!email) return alert('Please enter email');
    
    try {
      await axios.post('/forgot-password', { email });
      currentEmail = email;
      document.getElementById('emailDisplay').textContent = email;
      emailStep.classList.add('d-none');
      otpStep.classList.remove('d-none');
      document.getElementById('forgotTitle').textContent = 'Enter OTP';
    } catch (err) {
      alert(`❌ ${err.response?.data?.msg || 'Error sending OTP'}`);
    }
  }
  
  // Step 2: Verify OTP
  else if (!otpStep.classList.contains('d-none')) {
    const otp = document.getElementById('otp-input').value.trim();
    if (!otp || otp.length !== 6) {
      alert('❌ Enter valid 6-digit OTP');
      document.getElementById('otp-input').focus();
      return;
    }
    
    try {
      await axios.post('/verify-otp', { email: currentEmail, otp });
      otpStep.classList.add('d-none');
      passwordStep.classList.remove('d-none');
      document.getElementById('forgotTitle').textContent = 'New Password';
    } catch (err) {
      alert(`❌ ${err.response?.data?.msg || 'Invalid OTP'}`);
    }
  }
  
  // Step 3: Reset Password
  else if (!passwordStep.classList.contains('d-none')) {
    const password = document.getElementById('new-password').value;
    const confirmPassword = document.getElementById('confirm-password').value;
    
    if (!password || password.length < 6) {
      alert('❌ Password must be 6+ characters');
      document.getElementById('new-password').focus();
      return;
    }
    
    if (!confirmPassword || password !== confirmPassword) {
      alert('❌ Passwords do not match!');
      document.getElementById('confirm-password').focus();
      return;
    }
    
    try {
      await axios.post('/reset-password-otp', { email: currentEmail, password });
      bootstrap.Modal.getInstance(document.getElementById('forgotModal')).hide();
      alert('✅ Password reset successful! Please login with new password.');
      
      // Reset form
      ['forgot-email', 'otp-input', 'new-password', 'confirm-password'].forEach(id => 
        document.getElementById(id).value = ''
      );
    } catch (err) {
      alert(`❌ ${err.response?.data?.msg || 'Reset failed'}`);
    }
  }
});

// Back buttons
document.getElementById('backToEmail')?.addEventListener('click', () => {
  document.getElementById('emailStep').classList.remove('d-none');
  document.getElementById('otpStep').classList.add('d-none');
  document.getElementById('forgotTitle').textContent = 'Forgot Password';
});

document.getElementById('backToOtp')?.addEventListener('click', () => {
  document.getElementById('otpStep').classList.remove('d-none');
  document.getElementById('passwordStep').classList.add('d-none');
  document.getElementById('forgotTitle').textContent = 'Enter OTP';
});

// Dashboard
async function loadDashboard() {
  const welcomeEl = document.getElementById('welcome-msg');
  const msgEl = document.getElementById('dashboard-msg');
  try {
    const { data } = await axios.get('/dashboard');
    welcomeEl.textContent = data.msg;
    if (msgEl) msgEl.innerHTML = '<div class="alert alert-success">Dashboard loaded successfully!</div>';
  } catch {
    localStorage.removeItem('token');
    showPage('login-page');
  }
}

// Logout
document.getElementById('logout-btn')?.addEventListener('click', () => {
  localStorage.removeItem('token');
  showPage('login-page');
});
