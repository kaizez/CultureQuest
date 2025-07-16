// Language translations object
const translations = {
  en: {
    title: "CULTUREQUEST",
    idLogin: "ID Login",
    username: "Username",
    password: "Password",
    loginError: "Your ID or password is incorrect. Please try again.",
    remember: "Remember Me",
    loginBtn: "Sign in",
    forgot: "Forgot your password or ID?",
    signup: "Sign up"
  },
  ko: {
    title: "CULTUREQUEST",
    idLogin: "아이디 로그인",
    username: "아이디",
    password: "비밀번호",
    loginError: "아이디 또는 비밀번호가 올바르지 않습니다.",
    remember: "로그인 상태 유지",
    loginBtn: "로그인",
    forgot: "비밀번호 또는 아이디 를 잊으셨나요?",
    signup: "회원가입"
  },
  es: {
    title: "CULTUREQUEST",
    idLogin: "Iniciar sesión con ID",
    username: "Nombre de usuario",
    password: "Contraseña",
    loginError: "El ID o la contraseña son incorrectos.",
    remember: "Recuérdame",
    loginBtn: "Iniciar sesión",
    forgot: "¿Olvidaste tu contraseña o ID?",
    signup: "Regístrate"
  },
  zh: {
    title: "CULTUREQUEST",
    idLogin: "ID 登录",
    username: "用户名",
    password: "密码",
    loginError: "ID 或密码错误。请再试一次。",
    remember: "记住我",
    loginBtn: "登录",
    forgot: "忘记了密码 或 ID？",
    signup: "注册"
  },
  ms: {
    title: "CULTUREQUEST",
    idLogin: "Log Masuk ID",
    username: "Nama Pengguna",
    password: "Kata Laluan",
    loginError: "ID atau kata laluan salah. Sila cuba lagi.",
    remember: "Ingat Saya",
    loginBtn: "Log Masuk",
    forgot: "Terlupa kata laluan atau ID anda?",
    signup: "Daftar"
  },
  hi: {
    title: "CULTUREQUEST",
    idLogin: "आईडी लॉगिन",
    username: "उपयोगकर्ता नाम",
    password: "पासवर्ड",
    loginError: "आपकी ID या पासवर्ड गलत है। कृपया पुनः प्रयास करें।",
    remember: "मुझे याद रखें",
    loginBtn: "लॉगिन करें",
    forgot: "क्या आपने पासवर्ड या ID भूल गए?",
    signup: "साइन अप करें"
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

  // Update all texts and placeholders
  updateText("title", "title");
  updateText("id-login-btn", "idLogin");
  updateText("login-btn", "loginBtn");
  updateText("forgot", "forgot");
  updateText("signup", "signup");

  // Update placeholders
  document.querySelectorAll("input[name=username]").forEach(el => {
    el.placeholder = textMap.username || el.placeholder;
  });
  document.querySelectorAll("input[name=password]").forEach(el => {
    el.placeholder = textMap.password || el.placeholder;
  });
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
