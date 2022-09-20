import Navbar from "./Navbar";
import React, { useState, useContext } from "react";
import { useNavigate } from "react-router";

const Logout = () => {
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
            navigate("/")
            console.log(localStorage.getItem("token"));
        } else {
            console.log("try again");
        }
    }
  return (
    <div><button onClick={handleClick}>logout</button></div>
  )
}

export default Logout