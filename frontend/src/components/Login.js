import Navbar from "./Navbar";
import React, { useState, useContext } from "react";
import { useNavigate } from "react-router";
// import pic from '../images/pic.jpg'

const Login = () => {
  const [credentials, setcredentials] = useState({
    username: "",
    password: "",
  });
  const navigate = useNavigate();

  const handleChange = (e) => {
    setcredentials({ ...credentials, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    //API Call
    const response = await fetch("http://127.0.0.1:8000/login/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Request-Headers": "http://127.0.0.1:3000/",
      },
      body: JSON.stringify({
        username: credentials.username,
        password: credentials.password,
      }),
    });
    const json = await response.json();
    console.log(json);
    if (!response.ok) {
      console.log({ status: response.status, message: response.statusText });
    } else {
      //Save the authtoken and redirect
      localStorage.setItem("token", json.access);
      const response1 = await fetch("http://127.0.0.1:8000/profile/", {
        method: "GET",
        headers: {
          Authorization: `Bearer ${localStorage.getItem("token")}`,
          "Access-Control-Request-Headers": "http://127.0.0.1:3000/",
        },
      });
      const json1 = await response1.json();
      console.log(json1);
      navigate("/");
    }
  };
  return (
    <div className="login-main">
      <Navbar />
      <div className="card">
        <form onSubmit={handleSubmit}>
          <h1>Sign In</h1>
          <div className="mb-3 form-item">
            <label htmlFor="username" className="col-form-label">
              Username
            </label>
            <input
              type="text"
              className="form-control"
              id="username"
              name="username"
              value={credentials.username}
              onChange={handleChange}
            />
          </div>
          <div className="mb-3 form-item">
            <label htmlFor="inputPassword" className="col-form-label">
              Password
            </label>
            <input
              type="password"
              className="form-control"
              id="inputPassword"
              name="password"
              value={credentials.password}
              onChange={handleChange}
            />
          </div>
          <button type="submit" className="btn btn-primary">
            Submit
          </button>
        </form>
      </div>
      {/* <img src={pic} alt="" /> */}
      {/* <div className="login">
      <form onSubmit={handleSubmit}>
      <div className="mb-3">
          <label htmlFor="username" className="col-form-label">
            Username
          </label>
            <input
              type="text"
              className="form-control"
              id="username"
              name="username"
              value={credentials.username}
              onChange={handleChange}
            />
        </div>
        <div className="mb-3">
          <label htmlFor="inputPassword" className="col-form-label">
            Password
          </label>
            <input
              type="password"
              className="form-control"
              id="inputPassword"
              name="password"
              value={credentials.password}
              onChange={handleChange}
            />
        </div>
        <button type="submit" className="btn btn-primary">
          Submit
        </button>
        </form>
      </div> */}
    </div>
  );
};

export default Login;
