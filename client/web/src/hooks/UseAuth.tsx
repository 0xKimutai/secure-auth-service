import { useContext } from "react";
import { AuthContext } from "../context/AuthContext";

interface LoginPayload {
  identifier: string; // can be email, username, or mobileNumber
  password: string;
}

interface SignupPayload {
  email: string;
  username: string;
  mobileNumber: string;
  password: string;
  confirmPassword: string;
}

export const useAuth = () => {
  const context = useContext(AuthContext);

  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }

  // ----------------------
  // LOGIN
  // ----------------------
  const login = async ({ identifier, password }: LoginPayload) => {
    try {
      await context.login(identifier, password);
    } catch (err: any) {
      let errorMessage = "Login failed";
      if (err instanceof Error) errorMessage = err.message;
      throw new Error(errorMessage);
    }
  };

  // ----------------------
  // SIGNUP
  // ----------------------
  const signup = async (payload: SignupPayload) => {
    try {
      // Map frontend mobileNumber to backend 'mobile'
      await context.signup({
        username: payload.username,
        email: payload.email,
        mobile: payload.mobileNumber,
        password: payload.password,
        confirmPassword: payload.confirmPassword,
      });
    } catch (err: any) {
      let errorMessage = "Signup failed";
      if (err instanceof Error) errorMessage = err.message;
      throw new Error(errorMessage);
    }
  };

  return {
    ...context,
    login,
    signup,
  };
};
