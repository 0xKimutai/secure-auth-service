import { useAuth } from "../hooks/UseAuth";

const Home = () => {
  const { user, logout } = useAuth();

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-gray-50">
      <h1 className="text-3xl font-bold mb-4">Welcome, {user?.email} 🎉</h1>
      <button
        onClick={logout}
        className="px-4 py-2 bg-red-600 text-white rounded-lg shadow hover:bg-red-700"
      >
        Logout
      </button>
    </div>
  );
};

export default Home;
