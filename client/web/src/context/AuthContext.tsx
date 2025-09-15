import { createContext, useState, useEffect, ReactNode } from "react";
import { useNavigate } from "react-router-dom";

type User = {
  email?: string;
  username?: string;
  mobile?: string;
  // Add other user properties as needed
};

type AuthContextType = {
  user: User | null;
  token: string | null;
  login: (identifier: string, password: string) => Promise<void>;
  signup: (payload: {
    email?: string;
    username?: string;
    mobile?: string;
    password: string;
    confirmPassword: string;
  }) => Promise<void>;
  logout: () => void;
};

export const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider = ({ children }: { children: ReactNode }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const navigate = useNavigate();
  const API_URL = "http://localhost:8080";

  // Load user and token from localStorage on initial render
  useEffect(() => {
    const savedToken = localStorage.getItem("token");
    const savedUser = localStorage.getItem("user");
    if (savedToken && savedUser) {
      try {
        const parsedUser = JSON.parse(savedUser);
        setUser(parsedUser);
        setToken(savedToken);
      } catch {
        localStorage.removeItem("token");
        localStorage.removeItem("user");
      }
    }
  }, []);

  // ---- Signup function ----
  const signup = async (payload: {
    email?: string;
    username?: string;
    mobile?: string;
    password: string;
    confirmPassword: string;
  }) => {
    const response = await fetch(`${API_URL}/api/v1/auth/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.message || "Signup failed");
    }

    const data = await response.json();
    setToken(data.token);
    setUser({ email: data.email, username: data.username, mobile: data.mobile });

    localStorage.setItem("token", data.token);
    localStorage.setItem("user", JSON.stringify({ email: data.email, username: data.username, mobile: data.mobile }));
    navigate("/");
  };

  // ---- Login function ----
  const login = async (identifier: string, password: string) => {
    const response = await fetch(`${API_URL}/api/v1/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ identifier, password }),
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.message || "Login failed");
    }

    const data = await response.json();
    setToken(data.token);
    setUser({ email: data.email, username: data.username, mobile: data.mobile });

    localStorage.setItem("token", data.token);
    localStorage.setItem("user", JSON.stringify({ email: data.email, username: data.username, mobile: data.mobile }));
    navigate("/");
  };

  // ---- Logout function ----
  const logout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem("user");
    localStorage.removeItem("token");
    navigate("/login");
  };

  return (
    <AuthContext.Provider value={{ user, token, login, signup, logout }}>
      {children}
    </AuthContext.Provider>
  );
};
