import React,{useState} from 'react'
import { youtube } from './apis';
const Home = () => {
  
  
  const [Tech, setTech] = useState("");
  const handleChange = (e) =>{
    setTech(e.target.value); 
  }
  const handleSubmit = (e) =>{
    console.log(Tech);
  }
  return (
    <div>
      <button onClick={youtube}>Click</button>
      <form onSubmit={handleSubmit} className="form-inline d-flex justify-content-center md-form form-sm mt-0">
        <i className="fas fa-search" aria-hidden="true"></i>
        <input className="form-control form-control-sm ml-3 w-75" type="text" placeholder="Search"aria-label="Search" name="tech"
          value={Tech} onChange={handleChange}/>
    </form>
    </div>
    // <div>
    //     <button onClick={updateState()}>Github repos</button>
    // </div>
  )
}

export default Home