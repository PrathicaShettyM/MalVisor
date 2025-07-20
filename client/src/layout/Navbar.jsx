import { Link, useLocation } from "react-router-dom";
import {
  FaNetworkWired,
  FaProjectDiagram,
  FaRobot,
  FaShieldAlt,
} from "react-icons/fa";

const Navbar = () => {
  const location = useLocation();

  return (
    <nav className="bg-gradient-to-r from-blue-900 to-indigo-900 text-white shadow-lg">
      <div className="max-w-7xl mx-auto px-8 py-4 flex justify-between items-center">
        <div className="flex items-center space-x-3">
          <FaShieldAlt className="w-8 h-8 text-white" />
          <h1 className="text-2xl font-bold tracking-wide text-white">MalVisor</h1>
        </div>
        <div className="flex space-x-6 text-sm font-medium">
          
          <Link
            to="/description"
            className={`flex items-center gap-2 px-3 py-2 rounded-lg hover:bg-blue-800 hover:text-white transition-all ${
              location.pathname === "/description" ? "bg-blue-800 text-white font-semibold" : "text-white"
            }`}
          >
            <FaProjectDiagram className="w-4 h-4" />
            <span>Topic Introduction</span>
          </Link>

          <Link
            to="/"
            className={`flex items-center gap-2 px-3 py-2 rounded-lg hover:bg-blue-800 hover:text-white transition-all ${
              location.pathname === "/" ? "bg-blue-800 text-white font-semibold" : "text-white"
            }`}
          >
            <FaNetworkWired className="w-4 h-4" />
            <span>Static Analysis</span>
          </Link>

          <Link
            to="/ask-ai"
            className={`flex items-center gap-2 px-3 py-2 rounded-lg hover:bg-blue-800 hover:text-white transition-all ${
              location.pathname === "/ask-ai" ? "bg-blue-800 text-white font-semibold" : "text-white"
            }`}
          >
            <FaRobot className="w-4 h-4" />
            <span>Ask AI</span>
          </Link>

        </div>
      </div>
    </nav>
  );
};

export default Navbar;