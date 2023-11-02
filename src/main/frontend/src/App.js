import React, {useEffect, useState} from 'react';
import axios from 'axios';
import {Route, Routes} from "react-router-dom";

const Login = import('./pages/Login');

const path = '/jwtstudy';
function App() {
  const [index, setIndex] = useState('none');

  useEffect(() => {
    axios.get(path+'/index')
        .then(response => setIndex(response.data))
        .catch(error => console.log(error))
  }, []);

  return (
      <div className="App">
          <h1 className="App-title">Welcome to React</h1>
          <Routes>
              <Route path="/" element={
                  <>
                  <div>
                      백엔드에서 가져온 데이터입니다 : {index}
                  </div>

                  <Login />
                  </>
              } >
              </Route>
          </Routes>
      </div>
  );
}

export default App;