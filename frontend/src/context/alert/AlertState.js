import { useState } from "react";
import alertContext from "./alertContext";

const AlertState = (props) => {
  const capitalize = (word) => {
    if(word === "danger") word = "error";
    if(word)
        return word[0].toUpperCase() + word.slice(1).toLowerCase();
    else
        return null;
  };

  const showAlert = (alert) => {
      setalert({type: alert.type, msg: alert.msg});
      setTimeout(() => {
          setdisplay("none");
      }, 1500);
  }
  const [alert, setalert] = useState({type: "", msg: ""});
  const [display, setdisplay] = useState("none")
  
  
  return (
      <>
    <alertContext.Provider value={{showAlert, setdisplay}}>
      <div style={{ height: "50px", display: display }}>
        {alert && (
          <div
            className={`alert alert-${alert.type} alert-dismissible fade show`}
            role="alert"
          >
            {capitalize(alert.type)}: <strong>{alert.msg}</strong>
          </div>
        )}
      </div>
      {props.children}

    </alertContext.Provider>

    </>

  );
};

export default AlertState;
