import { Link } from "react-router-dom";

export const ForgotPassword = () => {
  return (
    <div className="h-screen bg-gray-50 flex items-center justify-center px-4">
      <div className="w-full max-w-md bg-white p-8 rounded-2xl shadow-lg border border-gray-200">
        <h2 className="text-2xl font-bold text-gray-800 text-center mb-6">
          Reset your password
        </h2>

        <form className="space-y-5">
          <div>
            <label
              className="block text-sm text-gray-600 mb-1"
              htmlFor="identifier"
            >
              Email / Username / Phone Number
            </label>
            <input
              type="text"
              name="identifier"
              id="identifier"
              placeholder="Enter your account identifier"
              className="w-full px-4 py-3 rounded-lg bg-gray-50 text-gray-800 placeholder-gray-400 border border-gray-300 focus:outline-none focus:ring-2 focus:ring-indigo-500"
              required
            />
          </div>

          <button
            type="submit"
            className="w-full bg-indigo-600 hover:bg-indigo-500 text-white py-3 rounded-lg font-semibold transition duration-200"
          >
            Send Reset Link
          </button>
        </form>

        <p className="text-center text-sm text-gray-500 mt-6">
          Remembered your password?{" "}
          <Link
            to="/login"
            className="text-indigo-600 font-medium hover:underline"
          >
            Go back to login
          </Link>
        </p>
      </div>
    </div>
  );
};
