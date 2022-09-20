import Navbar from "./Navbar";
import React, { useState } from "react";
import { useNavigate } from "react-router";

const Profile = () => {
  const [credentials, setcredentials] = useState({ linkedin: "", github: "", skills_to_learn: "" });
  const navigate = useNavigate();
  const handleChange = (e) => {
    setcredentials({ ...credentials, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    //API Call
    const response = await fetch("http://127.0.0.1:8000/connect/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Request-Headers": "http://127.0.0.1:3000/",
        "Authorization":`Bearer ${localStorage.getItem('token')}`,
      },
      body: JSON.stringify({
        linkedin: credentials.linkedin,
        github: credentials.github,
        skills_to_learn: credentials.skills_to_learn
      }),
    });
    const json = await response.json();
    console.log(json);
    if (!response.ok) {
      console.log({status: response.status, message: response.statusText});

    } else {
      navigate("/home");      
    }
  }
  return (
    <div className="profile-main">
      <Navbar />
      <div className="profile">
      <form onSubmit={handleSubmit}>
      <div className="mb-3">
          <label htmlFor="linkedin" className="col-form-label">
            Enter your Linkedin Profile link
          </label>
            <input
              type="url"
              className="form-control"
              id="linkedin"
              name="linkedin"
              value={credentials.username}
              onChange={handleChange}
            />
        </div>
        <div className="mb-3">
          <label htmlFor="github" className="form-label">
            Enter your Github Username
          </label>
          <input
            type="text"
            className="form-control"
            id="github"
            name="github"
            value={credentials.email}
            onChange={handleChange}
          />
        </div>
        <div className="mb-3">
          <label htmlFor="skills" className="col-form-label">
            What skills are you interested in learning?
          </label>
            <input
              type="text"
              className="form-control"
              id="skills"
              name="skills"
              value={credentials.fname}
              onChange={handleChange}
            />
        </div>
        
        <button type="submit" className="btn btn-primary">
          Submit
        </button>
        </form>
      </div>
    </div>
  )
}

export default Profile