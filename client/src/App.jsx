import {BrowserRouter as Router, Routes, Route, Navigate} from 'react-router-dom';
import Home from "./pages/Home";
import Description from './pages/Description';
import AskAI from './pages/AskAI';

function App() {
  
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Home/>}/>
        <Route path="/description" element={<Description/>}/>
        <Route path="/ask-ai" element={<AskAI/>}/>
      </Routes>
    </Router>
  )
}

export default App;