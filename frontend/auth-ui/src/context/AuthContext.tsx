import { createContext, useState, useEffect, ReactNode } from "react";
import { useNavigate } from "react-router-dom";

type User = {
  email: string;
  // Add other user properties as needed
};

type AuthContextType = {
  user: User | null;
  token: string | null;
  login: (email: string, password: string) => Promise<void>;
  signup: (email: string, password: string) => Promise<void>;
  logout: () => void;
};

export const AuthContext = createContext<AuthContextType | undefined>(
  undefined
);

export const AuthProvider = ({ children }: { children: ReactNode }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const navigate = useNavigate(); // ✅ must be at top

  // Load user and token from localStorage on initial render
  useEffect(() => {
    const savedToken = localStorage.getItem("token");
    const savedUser = localStorage.getItem("user");
    if (savedToken && savedUser) {
      try {
        const parsedUser = JSON.parse(savedUser);

        // Basic validation: must have email
        if (parsedUser?.email && savedToken.trim() !== "") {
          setUser(parsedUser);
          setToken(savedToken);
        } else {
          // clear invalid storage
          localStorage.removeItem("token");
          localStorage.removeItem("user");
        }
      } catch {
        localStorage.removeItem("token");
        localStorage.removeItem("user");
      }
    }
  }, []);

  // ---- Signup function ----
  const signup = async (email: string, password: string) => {
    const response = await fetch("http://localhost:8080/api/auth/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });

    if (!response.ok) {
      throw new Error("Signup failed");
    }

    const data = await response.json();
    setToken(data.token);
    setUser({ email: data.email });

    localStorage.setItem("token", data.token);
    localStorage.setItem("user", JSON.stringify({ email: data.email }));
    navigate("/");
  };

  // ---- Login function ----
  const login = async (email: string, password: string) => {
    const response = await fetch("http://localhost:8080/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });

    if (!response.ok) {
      throw new Error("Login failed");
    }

    const data = await response.json();
    setToken(data.token);
    setUser({ email: data.email });

    localStorage.setItem("token", data.token);
    localStorage.setItem("user", JSON.stringify({ email: data.email }));
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
