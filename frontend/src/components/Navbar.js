import React from "react";
import { Link } from "react-router-dom";
import { useNavigate } from "react-router";

const Navbar = () => {
  const navigate = useNavigate();

  const handleClick = async () => {
    const response = await fetch("http://127.0.0.1:8000/logout_token/", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Access-Control-Request-Headers": "http://127.0.0.1:3000/",
            "Authorization": `Bearer ${localStorage.getItem("token")}`
        }
    })
    const json = await response.json();
    console.log(json);
    if(response.ok)
    {   localStorage.removeItem("token")
        navigate("/login")
        console.log(localStorage.getItem("token"));
    } else {
        console.log("try again");
    }
}
  return (
    <div className="nbar">
      <nav className="navbar navbar-expand-sm">
        <div className="container-fluid ">
          <Link className="navbar-brand" to="/">
            Toolkit
          </Link>
          <button
            className="navbar-toggler"
            type="button"
            data-bs-toggle="collapse"
            data-bs-target="#navbarSupportedContent"
            aria-controls="navbarSupportedContent"
            aria-expanded="false"
            aria-label="Toggle navigation"
          >
            <span className="navbar-toggler-icon"></span>
          </button>
          <div
            className="collapse navbar-collapse justify-content-end"
            id="navbarSupportedContent"
          >
            
            {!localStorage.getItem("token") ? (
              <form className="d-flex">
                <Link className="nav-link" aria-current="page" to="/">
                  Home
                </Link>
                <Link className="nav-link" to="/about">
                  About
                </Link>
                <Link className="nav-link  pr-5" to="/contact">
                  Contact
                </Link>
                <Link
                  className="nav-link"
                  to="/register"
                  role="button"
                >
                  Register
                </Link>
                <Link
                  className="nav-link"
                  to="/login"
                  role="button"
                >
                  Login
                </Link>
                
              </form>
            ) : (
              <div className="d-flex">
              <form className="d-flex">
                <Link className="nav-link" aria-current="page" to="/">
                  Home
                </Link>
                <Link className="nav-link" to="/about">
                  About
                </Link>
                <Link className="nav-link  pr-5" to="/contact">
                  Contact
                </Link>
              </form>
                <button
                  className="nav-link logoutbtn"
                  onClick={handleClick}
                >
                  Logout
                </button>
              </div>
            )}
          </div>
        </div>
      </nav>
    </div>
  );
};

export default Navbar;
