import './App.css';
import Landingpage from './components/Landingpage';
import { BrowserRouter,
  Routes,
  Route,} from 'react-router-dom';
import About from './components/About';
import Contact from './components/Contact';
import Register from './components/Register';
import Login from './components/Login';
import Home from './components/Home';
import Profile from './components/Profile';
import Logout from './components/Logout';
// import Navbar from './components/Navbar';


function App() {
  return (
    <div className='main'>
      <BrowserRouter>
      <Routes>
            <Route
              exact
              activeClassName="active"
              path="/"
              element={
                <Landingpage/>
              }
            />
            <Route
              exact
              activeClassName="active"
              path="/about"
              element={
                <About/>
              }
            />
            <Route
              exact
              activeClassName="active"
              path="/contact"
              element={
                <Contact/>
              }
            />
            <Route
              exact
              activeClassName="active"
              path="/register"
              element={
                <Register/>
              }
            />
            <Route
              exact
              activeClassName="active"
              path="/login"
              element={
                <Login/>
              }
            />
            <Route
              exact
              activeClassName="active"
              path="/home"
              element={
                <Home/>
              }
            />
            <Route
              exact
              activeClassName="active"
              path="/profile"
              element={
                <Profile/>
              }
            />
            <Route
              exact
              activeClassName="active"
              path="/logout"
              element={
                <Logout/>
              }
            />
          </Routes>
      </BrowserRouter>
    </div>
  );
}

export default App;
