// auth.js — Gestión de roles y protección de páginas admin

function decodeToken() {
    const token = localStorage.getItem("token");
    if (!token) return null;

    try {
        const payload = JSON.parse(atob(token.split(".")[1]));
        return payload;
    } catch {
        return null;
    }
}

function getUserRole() {
    const payload = decodeToken();
    return payload ? payload.role : null;
}

function isAdmin() {
    return getUserRole() === "admin";
}

function insertAdminButton() {
    if (!isAdmin()) return;

    const adminBtn = document.createElement("a");
    adminBtn.href = "admin-dashboard.html";
    adminBtn.textContent = "Admin";
    adminBtn.className = "admin-button";

    adminBtn.style.position = "fixed";
    adminBtn.style.top = "20px";
    adminBtn.style.right = "20px";
    adminBtn.style.background = "#2d3436";
    adminBtn.style.color = "white";
    adminBtn.style.padding = "10px 18px";
    adminBtn.style.borderRadius = "8px";
    adminBtn.style.zIndex = "9999";
    adminBtn.style.fontWeight = "600";
    adminBtn.style.fontSize = "14px";
    adminBtn.style.boxShadow = "0 2px 8px rgba(0,0,0,0.2)";
    adminBtn.style.textDecoration = "none";
    adminBtn.style.cursor = "pointer";

    document.body.appendChild(adminBtn);
}

function protectAdminPage() {
    if (!isAdmin()) {
        alert("No tienes permiso para acceder a esta página.");
        window.location.href = "login.html";
    }
}

document.addEventListener("DOMContentLoaded", insertAdminButton);
