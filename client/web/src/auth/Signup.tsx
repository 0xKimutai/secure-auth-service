import { useEffect, useState } from "react";
import { useAuth } from "../hooks/UseAuth";
import keycloak from "../services/keycloak";

export const Signup = () => {
  const { signup } = useAuth();
  
  const [username, setUsername] = useState("");
  const [mobileNumber, setMobileNumber] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const initKeycloak = async () => {
      try {
        const authenticated = await keycloak.init({ onLoad: "check-sso" });
        if (authenticated) {
          localStorage.setItem("token", keycloak.token || "");
          const profile = await keycloak.loadUserProfile();
          localStorage.setItem("user", JSON.stringify(profile));
        }
      } catch (err) {
        console.error("Keycloak initialization failed:", err);
        setError("Authentication failed. Please try again.");
      }
    };

    initKeycloak();
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (password !== confirmPassword) {
      setError("Passwords do not match");
      return;
    }

    if (!/^\+?\d{7,15}$/.test(mobileNumber)) {
      setError("Invalid mobile number");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      await signup({ 
        email, 
        password, 
        username, 
        mobileNumber,
        confirmPassword 
      });
    } catch (err: any) {
      setError(err.message || "Failed to create an account");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-gradient-to-br from-pink-500 via-red-500 to-yellow-500">
      <div className="w-full max-w-md bg-white/90 backdrop-blur-md rounded-2xl shadow-2xl p-8">
        <h2 className="text-3xl font-extrabold text-center text-gray-800 mb-6">
          Create Account 🚀
        </h2>

        {error && (
          <div className="mb-4 text-sm text-red-700 bg-red-100 border border-red-300 p-3 rounded-lg">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-5">
          {/* Username */}
          <div>
            <label className="block text-sm font-semibold text-gray-700">
              Username
            </label>
            <input
              type="text"
              className="mt-2 w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-pink-500 focus:border-pink-500 focus:outline-none transition"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
          </div>

          {/* Mobile Number */}
          <div>
            <label className="block text-sm font-semibold text-gray-700">
              Mobile Number
            </label>
            <input
              type="tel"
              className="mt-2 w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-pink-500 focus:border-pink-500 focus:outline-none transition"
              value={mobileNumber}
              onChange={(e) => setMobileNumber(e.target.value)}
              placeholder="+254712345678"
              required
            />
          </div>

          {/* Email */}
          <div>
            <label className="block text-sm font-semibold text-gray-700">
              Email Address
            </label>
            <input
              type="email"
              className="mt-2 w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-pink-500 focus:border-pink-500 focus:outline-none transition"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>

          {/* Password */}
          <div>
            <label className="block text-sm font-semibold text-gray-700">
              Password
            </label>
            <input
              type="password"
              className="mt-2 w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-pink-500 focus:border-pink-500 focus:outline-none transition"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>

          {/* Confirm Password */}
          <div>
            <label className="block text-sm font-semibold text-gray-700">
              Confirm Password
            </label>
            <input
              type="password"
              className="mt-2 w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-pink-500 focus:border-pink-500 focus:outline-none transition"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2 px-4 bg-pink-600 text-white font-semibold rounded-lg shadow-md hover:bg-pink-700 hover:scale-[1.02] transition disabled:opacity-50"
          >
            {loading ? "Signing up..." : "Sign Up"}
          </button>
        </form>

        <p className="text-sm text-center mt-6 text-gray-700">
          Already have an account?{" "}
          <a href="/login" className="text-pink-600 font-medium hover:underline">
            Login
          </a>
        </p>
      </div>
    </div>
  );
};
