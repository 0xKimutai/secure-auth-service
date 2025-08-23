// App.tsx
import { Routes, Route } from "react-router-dom";
import Home from "./pages/Home";
import { Login } from "./auth/Login";
import { Signup } from "./auth/Signup";
import { ForgotPassword } from "./auth/ForgotPassword";
import ProtectedRoute from "./components/ProtectedRoute";

function App() {
  return (
    <Routes>
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <Home />
          </ProtectedRoute>
        }
      />
      <Route path="/login" element={<Login />} />
      <Route path="/signup" element={<Signup />} />
      <Route path="/forgot-password" element={<ForgotPassword />} />
    </Routes>
  );
}

export default App;
