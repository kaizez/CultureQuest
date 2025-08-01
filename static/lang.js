// Language translations object
const translations = {
  en: {
    title: "CultureQuest",
    welcomeBack: "Welcome Back",
    signInSubtitle: "Sign in to continue your cultural journey",
    username: "Username",
    password: "Password",
    usernamePlaceholder: "Enter your username",
    passwordPlaceholder: "Enter your password",
    staySignedIn: "Stay signed in",
    forgotPassword: "Forgot Password?",
    signIn: "Sign In",
    orContinueWith: "or continue with",
    google: "Google",
    newToCultureQuest: "New to CultureQuest?",
    createAccount: "Create Account",
    showPassword: "Show password",
    hidePassword: "Hide password",
    usernameHelp: "Enter your username",
    passwordHelp: "Your password must be at least 8 characters long",
    // Signup page translations
    createAccount: "Create Account",
    joinCommunity: "Join our global cultural community",
    emailAddress: "Email Address",
    emailPlaceholder: "Enter your email address",
    emailHelp: "We'll send a verification link to this email",
    emailValid: "Valid email format",
    emailTaken: "Email is already taken",
    signUp: "Sign Up"
  },
  ko: {
    title: "CultureQuest",
    welcomeBack: "다시 오신 것을 환영합니다",
    signInSubtitle: "문화 여행을 계속하려면 로그인하세요",
    username: "사용자명",
    password: "비밀번호",
    usernamePlaceholder: "사용자명을 입력하세요",
    passwordPlaceholder: "비밀번호를 입력하세요",
    staySignedIn: "로그인 상태 유지",
    forgotPassword: "비밀번호를 잊으셨나요?",
    signIn: "로그인",
    orContinueWith: "또는 다음으로 계속",
    google: "Google",
    newToCultureQuest: "CultureQuest가 처음이신가요?",
    createAccount: "계정 만들기",
    showPassword: "비밀번호 보기",
    hidePassword: "비밀번호 숨기기",
    usernameHelp: "사용자명을 입력하세요",
    passwordHelp: "비밀번호는 최소 8자 이상이어야 합니다",
    joinCommunity: "글로벌 문화 커뮤니티에 참여하세요",
    emailAddress: "이메일 주소",
    emailPlaceholder: "이메일 주소를 입력하세요",
    emailHelp: "이 이메일로 인증 링크를 보내드립니다",
    emailValid: "유효한 이메일 형식",
    emailTaken: "이미 사용 중인 이메일입니다",
    signUp: "회원가입"
  },
  es: {
    title: "CultureQuest",
    welcomeBack: "Bienvenido de vuelta",
    signInSubtitle: "Inicia sesión para continuar tu viaje cultural",
    username: "Nombre de usuario",
    password: "Contraseña",
    usernamePlaceholder: "Ingresa tu nombre de usuario",
    passwordPlaceholder: "Ingresa tu contraseña",
    staySignedIn: "Mantener sesión iniciada",
    forgotPassword: "¿Olvidaste tu contraseña?",
    signIn: "Iniciar sesión",
    orContinueWith: "o continúa con",
    google: "Google",
    newToCultureQuest: "¿Nuevo en CultureQuest?",
    createAccount: "Crear cuenta",
    showPassword: "Mostrar contraseña",
    hidePassword: "Ocultar contraseña",
    usernameHelp: "Ingresa tu nombre de usuario",
    passwordHelp: "Tu contraseña debe tener al menos 8 caracteres"
  },
  zh: {
    title: "CultureQuest",
    welcomeBack: "欢迎回来",
    signInSubtitle: "登录以继续您的文化之旅",
    username: "用户名",
    password: "密码",
    usernamePlaceholder: "输入您的用户名",
    passwordPlaceholder: "输入您的密码",
    staySignedIn: "保持登录",
    forgotPassword: "忘记密码？",
    signIn: "登录",
    orContinueWith: "或使用以下方式继续",
    google: "Google",
    newToCultureQuest: "初次使用 CultureQuest？",
    createAccount: "创建账户",
    showPassword: "显示密码",
    hidePassword: "隐藏密码",
    usernameHelp: "输入您的用户名",
    passwordHelp: "您的密码必须至少包含8个字符"
  },
  ms: {
    title: "CultureQuest",
    welcomeBack: "Selamat kembali",
    signInSubtitle: "Log masuk untuk meneruskan perjalanan budaya anda",
    username: "Nama pengguna",
    password: "Kata laluan",
    usernamePlaceholder: "Masukkan nama pengguna anda",
    passwordPlaceholder: "Masukkan kata laluan anda",
    staySignedIn: "Kekal log masuk",
    forgotPassword: "Lupa kata laluan?",
    signIn: "Log masuk",
    orContinueWith: "atau teruskan dengan",
    google: "Google",
    newToCultureQuest: "Baru ke CultureQuest?",
    createAccount: "Buat akaun",
    showPassword: "Tunjukkan kata laluan",
    hidePassword: "Sembunyikan kata laluan",
    usernameHelp: "Masukkan nama pengguna anda",
    passwordHelp: "Kata laluan anda mestilah sekurang-kurangnya 8 aksara"
  },
  hi: {
    title: "CultureQuest",
    welcomeBack: "वापसी पर स्वागत है",
    signInSubtitle: "अपनी सांस्कृतिक यात्रा जारी रखने के लिए साइन इन करें",
    username: "उपयोगकर्ता नाम",
    password: "पासवर्ड",
    usernamePlaceholder: "अपना उपयोगकर्ता नाम दर्ज करें",
    passwordPlaceholder: "अपना पासवर्ड दर्ज करें",
    staySignedIn: "साइन इन रहें",
    forgotPassword: "पासवर्ड भूल गए?",
    signIn: "साइन इन करें",
    orContinueWith: "या इसके साथ जारी रखें",
    google: "Google",
    newToCultureQuest: "CultureQuest पर नए हैं?",
    createAccount: "खाता बनाएं",
    showPassword: "पासवर्ड दिखाएं",
    hidePassword: "पासवर्ड छुपाएं",
    usernameHelp: "अपना उपयोगकर्ता नाम दर्ज करें",
    passwordHelp: "आपका पासवर्ड कम से कम 8 अक्षर का होना चाहिए"
  }
};

// Function to update the text content on the page
function updateLanguage(lang) {
  const textMap = translations[lang];
  if (!textMap) return;

  // Helper function to update text content if the translation exists
  function updateText(id, key) {
    const element = document.getElementById(id);
    if (element && textMap[key]) {
      element.innerText = textMap[key];
    }
  }

  // Helper function to update attributes
  function updateAttribute(id, attribute, key) {
    const element = document.getElementById(id);
    if (element && textMap[key]) {
      element.setAttribute(attribute, textMap[key]);
    }
  }

  // Update all text elements
  updateText("title", "title");
  updateText("welcome-back", "welcomeBack");
  updateText("sign-in-subtitle", "signInSubtitle");
  updateText("username-label", "username");
  updateText("password-label", "password");
  updateText("stay-signed-in", "staySignedIn");
  updateText("forgot-password-link", "forgotPassword");
  updateText("sign-in-btn", "signIn");
  updateText("or-continue-with", "orContinueWith");
  updateText("google-text", "google");
  updateText("new-to-culturequest", "newToCultureQuest");
  updateText("create-account", "createAccount");
  updateText("username-help", "usernameHelp");
  updateText("password-help", "passwordHelp");
  
  // Signup page elements
  updateText("create-account-title", "createAccount");
  updateText("join-community", "joinCommunity");
  updateText("email-label", "emailAddress");

  // Update placeholders
  const usernameInput = document.getElementById("username");
  if (usernameInput && textMap.usernamePlaceholder) {
    usernameInput.placeholder = textMap.usernamePlaceholder;
  }

  const passwordInput = document.getElementById("password");
  if (passwordInput && textMap.passwordPlaceholder) {
    passwordInput.placeholder = textMap.passwordPlaceholder;
  }

  const emailInput = document.getElementById("email");
  if (emailInput && textMap.emailPlaceholder) {
    emailInput.placeholder = textMap.emailPlaceholder;
  }

  // Update aria-labels for accessibility
  updateAttribute("toggle-password-btn", "aria-label", "showPassword");
}

// Adding an event listener to initialize language selection on page load
document.addEventListener("DOMContentLoaded", function () {
  const selector = document.getElementById("languageSelector");

  // Retrieve the stored language preference from localStorage or default to 'en'
  const storedLang = localStorage.getItem('language') || 'en';
  selector.value = storedLang;
  updateLanguage(storedLang); // Apply the stored language on page load

  // Update the language when the user selects a different language
  selector.addEventListener("change", function () {
    const lang = this.value;
    localStorage.setItem('language', lang); // Save the new language preference
    updateLanguage(lang); // Apply the selected language
  });
});
